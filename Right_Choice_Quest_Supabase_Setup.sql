-- Right Choice Quest — Supabase setup
-- Replace YOUR_ADMIN_EMAIL with the email used for the admin account in Supabase Authentication.
create extension if not exists pgcrypto;
create table if not exists public.quiz_attempts (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  hospital text not null,
  ward text not null,
  contact text not null,
  score integer not null check (score >= 0),
  total integer not null default 20 check (total > 0),
  duration_ms integer not null check (duration_ms >= 0),
  submitted_at timestamptz not null default now()
);
alter table public.quiz_attempts enable row level security;
drop policy if exists "participants can submit" on public.quiz_attempts;
create policy "participants can submit" on public.quiz_attempts for insert to anon, authenticated with check (true);
drop policy if exists "admin can read" on public.quiz_attempts;
create policy "admin can read" on public.quiz_attempts for select to authenticated using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL');
drop policy if exists "admin can delete" on public.quiz_attempts;
create policy "admin can delete" on public.quiz_attempts for delete to authenticated using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL');
create or replace function public.get_attempt_rank(p_attempt_id uuid)
returns integer language sql security definer set search_path = public as $$
  with target as (select score,duration_ms,submitted_at from public.quiz_attempts where id=p_attempt_id)
  select 1+count(*)::integer from public.quiz_attempts q,target t
  where q.score>t.score or (q.score=t.score and q.duration_ms<t.duration_ms) or (q.score=t.score and q.duration_ms=t.duration_ms and q.submitted_at<t.submitted_at);
$$;
revoke all on function public.get_attempt_rank(uuid) from public;
grant execute on function public.get_attempt_rank(uuid) to anon, authenticated;
grant usage on schema public to anon, authenticated;
grant insert on public.quiz_attempts to anon, authenticated;
grant select, delete on public.quiz_attempts to authenticated;
