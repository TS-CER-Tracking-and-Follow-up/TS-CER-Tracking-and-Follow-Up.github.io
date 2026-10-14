-- Special Project Management compatibility repair
-- Run AFTER special-project-management.sql has been applied.
-- Additive/data-preserving: does not drop tables or rows, and does not touch
-- cer_records, editor_lock, or any PR-release objects.
-- Safe to run more than once.

begin;

-- 1) Bridge the legacy single-task dependency column to the new array format.
alter table public.special_project_tasks
  add column if not exists dependency_ids uuid[] not null default '{}';

update public.special_project_tasks
set dependency_ids = array[depends_on_task_id]
where depends_on_task_id is not null
  and coalesce(cardinality(dependency_ids), 0) = 0;

-- The old guard expects the legacy depends_on_task_id field and conflicts with
-- the new spm_private guard. Remove only the obsolete trigger; retain its
-- function and all task rows.
drop trigger if exists special_project_tasks_guard_update
  on public.special_project_tasks;

-- 2) The legacy updates table stores text in "content"; the new module uses
-- "body". Keep both columns synchronized so old data and new inserts survive.
alter table public.special_project_updates
  add column if not exists body text;

update public.special_project_updates
set body = content
where body is null;

create or replace function spm_private.sync_update_body_content()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    if new.body is null then new.body := new.content; end if;
    if new.content is null then new.content := new.body; end if;
  else
    if new.body is distinct from old.body then
      new.content := new.body;
    elsif new.content is distinct from old.content then
      new.body := new.content;
    end if;
    if new.body is null then new.body := new.content; end if;
    if new.content is null then new.content := new.body; end if;
  end if;

  if new.body is null or length(trim(new.body)) = 0 then
    raise exception 'Update content cannot be empty';
  end if;
  return new;
end
$$;

revoke all on function spm_private.sync_update_body_content()
  from public, anon, authenticated;

drop trigger if exists spm_sync_update_body_content
  on public.special_project_updates;
create trigger spm_sync_update_body_content
before insert or update on public.special_project_updates
for each row execute function spm_private.sync_update_body_content();

-- 3) Align the default for newly created projects with the current module.
-- Existing project statuses are not rewritten.
alter table public.special_projects
  alter column status set default 'active';

commit;

-- Read-only verification (run after the repair):
-- select column_name, data_type
-- from information_schema.columns
-- where table_schema='public'
--   and table_name in ('special_project_tasks','special_project_updates')
--   and column_name in ('dependency_ids','depends_on_task_id','body','content')
-- order by table_name, column_name;
--
-- select tgname
-- from pg_trigger t
-- join pg_class c on c.oid=t.tgrelid
-- join pg_namespace n on n.oid=c.relnamespace
-- where n.nspname='public' and c.relname='special_project_tasks'
--   and not t.tgisinternal
-- order by tgname;
