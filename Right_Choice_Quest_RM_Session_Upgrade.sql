-- RIGHT CHOICE QUEST — RM NO-LOGIN / MULTI-SESSION + MASTER ADMIN
-- Run this entire script ONCE in Supabase SQL Editor.
-- RMs create and manage ward sessions without Supabase login.
-- Your master Supabase account can view all current and historical sessions.
-- Multiple sessions can be open simultaneously.

create extension if not exists pgcrypto;

-- SESSION TABLE UPDATES
create table if not exists public.quiz_sessions (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references auth.users(id) on delete set null,
  region_name text not null,
  session_name text not null,
  hospital text not null,
  ward text not null,
  status text not null default 'open' check (status in ('open','closed')),
  created_at timestamptz not null default now(),
  closed_at timestamptz
);

alter table public.quiz_sessions add column if not exists rm_name text;
alter table public.quiz_sessions add column if not exists manager_token_hash text;

-- Allow many regions/RMs to run activities at the same time.
drop index if exists one_open_rcq_session_per_admin;

-- ATTEMPTS BELONG TO A SESSION
alter table public.quiz_attempts
add column if not exists session_id uuid references public.quiz_sessions(id) on delete restrict;

create index if not exists quiz_attempts_session_rank_idx
on public.quiz_attempts(session_id, score desc, duration_ms asc, submitted_at asc);

-- MASTER ADMIN CHECK
create or replace function public.is_rcq_master_admin(p_user uuid default auth.uid())
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists(
    select 1 from auth.users
    where id=p_user
      and lower(email)=lower('ahmed.waqar@searlecompany.com')
  );
$$;

-- OPEN SESSION CHECK
create or replace function public.rcq_session_is_open(p_session_id uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists(select 1 from public.quiz_sessions where id=p_session_id and status='open');
$$;

-- RLS
alter table public.quiz_sessions enable row level security;
alter table public.quiz_attempts enable row level security;

-- Remove prior policies that conflict with this model.
drop policy if exists "sessions admin select" on public.quiz_sessions;
drop policy if exists "sessions admin insert" on public.quiz_sessions;
drop policy if exists "sessions admin update" on public.quiz_sessions;
drop policy if exists "master admin reads sessions" on public.quiz_sessions;
drop policy if exists "master admin creates sessions" on public.quiz_sessions;
drop policy if exists "master admin updates sessions" on public.quiz_sessions;

create policy "master admin reads sessions"
on public.quiz_sessions for select
to authenticated
using (public.is_rcq_master_admin());

drop policy if exists "participants can submit" on public.quiz_attempts;
drop policy if exists "admin can read" on public.quiz_attempts;
drop policy if exists "admin can delete" on public.quiz_attempts;
drop policy if exists "participants submit to open session" on public.quiz_attempts;
drop policy if exists "admins read own session attempts" on public.quiz_attempts;
drop policy if exists "master admin reads all attempts" on public.quiz_attempts;

create policy "participants submit to open session"
on public.quiz_attempts for insert
to anon, authenticated
with check (session_id is not null and public.rcq_session_is_open(session_id));

create policy "master admin reads all attempts"
on public.quiz_attempts for select
to authenticated
using (public.is_rcq_master_admin());

-- No DELETE policy: closed session history remains preserved.

-- PUBLIC: CREATE RM SESSION WITHOUT LOGIN.
-- A random manager token is returned once to the RM and only its SHA-256 hash is stored.
drop function if exists public.create_rm_session(text,text,text,text,text);
create function public.create_rm_session(
  p_region_name text,
  p_rm_name text,
  p_session_name text,
  p_hospital text,
  p_ward text
)
returns table(session_id uuid, manager_token text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
  v_token text;
  v_owner uuid;
begin
  if coalesce(trim(p_region_name),'')='' or coalesce(trim(p_rm_name),'')=''
     or coalesce(trim(p_session_name),'')='' or coalesce(trim(p_hospital),'')=''
     or coalesce(trim(p_ward),'')='' then
    raise exception 'All session fields are required.';
  end if;

  select id into v_owner from auth.users
  where lower(email)=lower('ahmed.waqar@searlecompany.com')
  limit 1;

  v_token := encode(gen_random_bytes(24),'hex');

  insert into public.quiz_sessions(owner_id,region_name,rm_name,session_name,hospital,ward,status,manager_token_hash)
  values(v_owner,trim(p_region_name),trim(p_rm_name),trim(p_session_name),trim(p_hospital),trim(p_ward),'open',
         encode(digest(v_token,'sha256'),'hex'))
  returning id into v_id;

  return query select v_id,v_token;
end;
$$;

-- PUBLIC: SAFE PARTICIPANT SESSION METADATA
drop function if exists public.get_public_session(uuid);
create function public.get_public_session(p_session_id uuid)
returns table(id uuid,region_name text,session_name text,hospital text,ward text,status text)
language sql stable security definer
set search_path = public
as $$
  select s.id,s.region_name,s.session_name,s.hospital,s.ward,s.status
  from public.quiz_sessions s
  where s.id=p_session_id;
$$;

-- RM: SESSION DETAILS VIA MANAGER TOKEN
drop function if exists public.get_rm_session(text);
create function public.get_rm_session(p_manager_token text)
returns table(
  id uuid,region_name text,rm_name text,session_name text,hospital text,ward text,status text,created_at timestamptz,closed_at timestamptz
)
language sql stable security definer
set search_path = public
as $$
  select s.id,s.region_name,s.rm_name,s.session_name,s.hospital,s.ward,s.status,s.created_at,s.closed_at
  from public.quiz_sessions s
  where s.manager_token_hash=encode(digest(p_manager_token,'sha256'),'hex')
  limit 1;
$$;

-- RM: ONLY THAT SESSION'S LEADERBOARD
drop function if exists public.get_rm_attempts(text);
create function public.get_rm_attempts(p_manager_token text)
returns table(
  id uuid,name text,hospital text,ward text,contact text,score integer,total integer,duration_ms integer,submitted_at timestamptz
)
language sql stable security definer
set search_path = public
as $$
  select q.id,q.name,q.hospital,q.ward,q.contact,q.score,q.total,q.duration_ms,q.submitted_at
  from public.quiz_attempts q
  join public.quiz_sessions s on s.id=q.session_id
  where s.manager_token_hash=encode(digest(p_manager_token,'sha256'),'hex')
  order by q.score desc,q.duration_ms asc,q.submitted_at asc;
$$;

-- RM: CLOSE ONLY THEIR TOKEN'S SESSION
drop function if exists public.close_rm_session(text);
create function public.close_rm_session(p_manager_token text)
returns table(id uuid,status text,closed_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  update public.quiz_sessions s
  set status='closed',closed_at=coalesce(s.closed_at,now())
  where s.manager_token_hash=encode(digest(p_manager_token,'sha256'),'hex')
    and s.status='open'
  returning s.id,s.status,s.closed_at;
end;
$$;

-- PARTICIPANT RANK — ONLY WITHIN THEIR OWN SESSION
create or replace function public.get_attempt_rank(p_attempt_id uuid)
returns integer
language sql security definer
set search_path = public
as $$
  with target as (
    select session_id,score,duration_ms,submitted_at
    from public.quiz_attempts where id=p_attempt_id
  )
  select 1+count(*)::integer
  from public.quiz_attempts q,target t
  where q.session_id=t.session_id
    and (
      q.score>t.score
      or (q.score=t.score and q.duration_ms<t.duration_ms)
      or (q.score=t.score and q.duration_ms=t.duration_ms and q.submitted_at<t.submitted_at)
    );
$$;

-- RPC PERMISSIONS
revoke all on function public.create_rm_session(text,text,text,text,text) from public;
grant execute on function public.create_rm_session(text,text,text,text,text) to anon,authenticated;

revoke all on function public.get_public_session(uuid) from public;
grant execute on function public.get_public_session(uuid) to anon,authenticated;

revoke all on function public.get_rm_session(text) from public;
grant execute on function public.get_rm_session(text) to anon,authenticated;

revoke all on function public.get_rm_attempts(text) from public;
grant execute on function public.get_rm_attempts(text) to anon,authenticated;

revoke all on function public.close_rm_session(text) from public;
grant execute on function public.close_rm_session(text) to anon,authenticated;

revoke all on function public.get_attempt_rank(uuid) from public;
grant execute on function public.get_attempt_rank(uuid) to anon,authenticated;

grant usage on schema public to anon,authenticated;
grant insert on public.quiz_attempts to anon,authenticated;
grant select on public.quiz_attempts to authenticated;
grant select on public.quiz_sessions to authenticated;

-- RESULTING WORKFLOW:
-- RM: same permanent app link -> enter Region/RM/Session/Hospital/Ward -> Create Session
-- -> QR + participant link -> live leaderboard -> Download CSV -> Close Current Session.
-- RM never needs the master Supabase login.
-- Master Admin: bottom-right "Master Admin" -> your Supabase email/password
-- -> all open and historical sessions across all regions.
