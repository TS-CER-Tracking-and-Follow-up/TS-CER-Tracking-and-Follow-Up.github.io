-- Add schedule columns for Project Management.
-- Additive only; no existing rows or CER data are deleted.
begin;
alter table public.special_project_tasks add column if not exists work_package text;
alter table public.special_project_tasks add column if not exists revised_finish date;
alter table public.special_project_tasks add column if not exists duration_days integer;
alter table public.special_project_tasks add column if not exists predecessors text;
alter table public.special_project_tasks add column if not exists responsibility text;
alter table public.special_project_tasks add column if not exists accountability text;
alter table public.special_project_tasks add column if not exists remarks text;
alter table public.special_project_tasks add column if not exists latest_update text;
commit;
