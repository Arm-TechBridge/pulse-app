begin;

-- USER PROFILES
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null
    check (username ~ '^[a-z0-9_]{3,24}$')
);

create function public.make_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into profiles(id, username)
  values (
    new.id,
    'user_' || substr(replace(new.id::text, '-', ''), 1, 16)
  );
  return new;
end;
$$;

create trigger create_user_profile
after insert on auth.users
for each row execute function public.make_profile();

-- Also cover users created before this SQL was run.
insert into public.profiles(id, username)
select
  id,
  'user_' || substr(replace(id::text, '-', ''), 1, 16)
from auth.users
on conflict do nothing;

-- MESSAGES
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender uuid not null references public.profiles(id) on delete cascade,
  recipient uuid not null references public.profiles(id) on delete cascade,
  body text,
  photo_path text,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  check (sender <> recipient),
  check (
    (body is not null and photo_path is null)
    or
    (body is null and photo_path is not null)
  )
);

create index messages_conversation
on public.messages(sender, recipient, created_at desc);

-- CALL SIGNALLING
create table public.calls (
  id uuid primary key default gen_random_uuid(),
  caller uuid not null references public.profiles(id) on delete cascade,
  callee uuid not null references public.profiles(id) on delete cascade,
  video boolean not null default false,
  offer jsonb not null,
  answer jsonb,
  status text not null default 'ringing'
    check (status in ('ringing', 'active', 'ended')),
  created_at timestamptz not null default now(),
  check (caller <> callee)
);

create index calls_incoming
on public.calls(callee, created_at desc);

-- SEND A MESSAGE: identity and photo expiry are set on the server.
create function public.send_message(
  p_to uuid,
  p_body text default null,
  p_path text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  result uuid;
begin
  if auth.uid() is null or auth.uid() = p_to then
    raise exception 'Invalid recipient';
  end if;

  if not exists(select 1 from profiles where id = p_to) then
    raise exception 'User not found';
  end if;

  if (
    select count(*) from messages
    where sender = auth.uid()
      and created_at > now() - interval '1 minute'
  ) >= 30 then
    raise exception 'Please wait before sending more messages';
  end if;

  if p_path is null then
    if p_body is null
      or length(trim(p_body)) = 0
      or length(p_body) > 2000 then
      raise exception 'Use a message between 1 and 2000 characters';
    end if;
  else
    if p_body is not null
      or split_part(p_path, '/', 1) <> auth.uid()::text then
      raise exception 'Invalid photo';
    end if;

    if exists(select 1 from messages where photo_path = p_path) then
      raise exception 'Photo already sent';
    end if;

    if not exists(
      select 1 from storage.objects
      where bucket_id = 'snaps' and name = p_path
    ) then
      raise exception 'Upload the photo first';
    end if;
  end if;

  insert into messages(sender, recipient, body, photo_path, expires_at)
  values (
    auth.uid(),
    p_to,
    p_body,
    p_path,
    case when p_path is not null
      then now() + interval '24 hours'
    end
  )
  returning id into result;

  return result;
end;
$$;

-- START A CALL
create function public.start_call(
  p_to uuid,
  p_video boolean,
  p_offer jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  result uuid;
begin
  if auth.uid() is null or auth.uid() = p_to then
    raise exception 'Invalid recipient';
  end if;

  if coalesce(p_offer->>'type', '') <> 'offer'
    or length(p_offer::text) > 100000 then
    raise exception 'Invalid call offer';
  end if;

  -- Lock both participants in a consistent order.
  perform pg_advisory_xact_lock(
    hashtextextended(least(auth.uid(), p_to)::text, 0)
  );
  perform pg_advisory_xact_lock(
    hashtextextended(greatest(auth.uid(), p_to)::text, 0)
  );

  if exists(
    select 1 from calls
    where (caller in (auth.uid(), p_to)
      or callee in (auth.uid(), p_to))
    and (
      (status = 'ringing'
        and created_at > now() - interval '90 seconds')
      or
      (status = 'active'
        and created_at > now() - interval '1 hour')
    )
  ) then
    raise exception 'A participant is already in a call';
  end if;

  if (
    select count(*) from calls
    where caller = auth.uid()
      and created_at > now() - interval '1 hour'
  ) >= 20 then
    raise exception 'Hourly call limit reached';
  end if;

  insert into calls(caller, callee, video, offer)
  values(auth.uid(), p_to, p_video, p_offer)
  returning id into result;

  return result;
end;
$$;

-- ACCEPT A CALL
create function public.answer_call(p_id uuid, p_answer jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(p_answer->>'type', '') <> 'answer'
    or length(p_answer::text) > 100000 then
    raise exception 'Invalid call answer';
  end if;

  update calls
  set answer = p_answer, status = 'active'
  where id = p_id
    and callee = auth.uid()
    and status = 'ringing'
    and created_at > now() - interval '90 seconds';

  if not found then
    raise exception 'This call has already ended';
  end if;
end;
$$;

-- END OR REJECT A CALL
create function public.end_call(p_id uuid)
returns void
language sql
security definer
set search_path = public
as $$
  update calls
  set status = 'ended'
  where id = p_id and auth.uid() in (caller, callee);
$$;

-- ACCESS CONTROL
alter table profiles enable row level security;
alter table messages enable row level security;
alter table calls enable row level security;

revoke all on profiles, messages, calls from anon, authenticated;
grant select on profiles, messages, calls to authenticated;
grant update(username) on profiles to authenticated;

create policy read_profiles
on profiles for select to authenticated
using (true);

create policy edit_own_username
on profiles for update to authenticated
using (id = auth.uid())
with check (id = auth.uid());

create policy read_own_messages
on messages for select to authenticated
using (
  auth.uid() in (sender, recipient)
  and (expires_at is null or expires_at > now())
);

create policy read_own_calls
on calls for select to authenticated
using (auth.uid() in (caller, callee));

revoke execute on function
  make_profile(),
  send_message(uuid, text, text),
  start_call(uuid, boolean, jsonb),
  answer_call(uuid, jsonb),
  end_call(uuid)
from public, anon;

grant execute on function
  send_message(uuid, text, text),
  start_call(uuid, boolean, jsonb),
  answer_call(uuid, jsonb),
  end_call(uuid)
to authenticated;

-- PRIVATE PHOTO STORAGE: 2 MB per file.
insert into storage.buckets(
  id, name, public, file_size_limit, allowed_mime_types
)
values (
  'snaps',
  'snaps',
  false,
  2097152,
  array['image/jpeg', 'image/png', 'image/webp']
);

create policy upload_own_snaps
on storage.objects for insert to authenticated
with check (
  bucket_id = 'snaps'
  and (storage.foldername(name))[1] = auth.uid()::text
);

create policy read_authorized_snaps
on storage.objects for select to authenticated
using (
  bucket_id = 'snaps'
  and exists (
    select 1 from public.messages m
    where m.photo_path = name
      and auth.uid() in (m.sender, m.recipient)
      and m.expires_at > now()
  )
);

commit;
