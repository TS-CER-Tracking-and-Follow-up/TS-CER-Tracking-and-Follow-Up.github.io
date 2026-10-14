-- Special Project Management RLS fix: allow signed-in users to create projects they own.
-- Safe/idempotent. Does not touch CER records, editor_lock, or PR-release tables.
-- Run this in Supabase SQL Editor, then click Save again.

begin;

alter table public.special_projects enable row level security;
grant select, insert, update, delete on public.special_projects to authenticated;

-- Recreate the exact owner-only INSERT rule expected by the app.
drop policy if exists sp_projects_create on public.special_projects;
create policy sp_projects_create
on public.special_projects
for insert
to authenticated
with check (owner_uid = (select auth.uid()));

-- Ensure users can read their own projects; shared projects remain readable
-- only when they are listed as a project member.
drop policy if exists sp_projects_read on public.special_projects;
create policy sp_projects_read
on public.special_projects
for select
to authenticated
using (
  owner_uid = (select auth.uid())
  or exists (
    select 1
    from public.special_project_members m
    where m.project_id = special_projects.id
      and m.user_id = (select auth.uid())
  )
);

commit;

-- Verification: should show sp_projects_create as INSERT / PERMISSIVE / authenticated.
select policyname, cmd, permissive, roles, with_check
from pg_policies
where schemaname = 'public'
  and tablename = 'special_projects'
order by policyname;
