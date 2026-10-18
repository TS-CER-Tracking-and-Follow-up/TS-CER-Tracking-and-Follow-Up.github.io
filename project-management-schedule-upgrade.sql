-- Project Management schedule upgrade and single-owner permission cleanup.
-- Additive schedule fields. Existing project/task/update records are retained.
-- Project ownership is assigned to the current tracker owner; collaborator memberships are removed,
-- per the owner's instruction that this is now a single-user tracking system.
begin;
alter table public.special_project_tasks add column if not exists work_package text;
alter table public.special_project_tasks add column if not exists revised_finish date;
alter table public.special_project_tasks add column if not exists duration_days integer;
alter table public.special_project_tasks add column if not exists predecessors text;
alter table public.special_project_tasks add column if not exists responsibility text;
alter table public.special_project_tasks add column if not exists accountability text;
alter table public.special_project_tasks add column if not exists remarks text;
alter table public.special_project_tasks add column if not exists latest_update text;
do $$
begin
  if not exists (select 1 from auth.users where id='df8689de-d769-43b9-b2a0-217999468d0b'::uuid) then
    raise exception 'Tracker owner user ID was not found in auth.users; no ownership changes were applied.';
  end if;
end $$;
alter table public.special_projects disable trigger spm_project_owner_guard;
update public.special_projects
set owner_uid='df8689de-d769-43b9-b2a0-217999468d0b'::uuid
where owner_uid is distinct from 'df8689de-d769-43b9-b2a0-217999468d0b'::uuid;
alter table public.special_projects enable trigger spm_project_owner_guard;
delete from public.special_project_members;
commit;
-- Verification:
-- select count(*) as projects_not_owned_by_tracker_owner
-- from public.special_projects
-- where owner_uid <> 'df8689de-d769-43b9-b2a0-217999468d0b'::uuid;
-- select count(*) as remaining_members from public.special_project_members;
