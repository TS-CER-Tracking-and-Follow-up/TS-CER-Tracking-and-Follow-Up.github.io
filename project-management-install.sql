-- ONE-TIME PROJECT MANAGEMENT SETUP / REPAIR
-- Run this entire file in Supabase Dashboard > SQL Editor > New query.
-- Additive/data-preserving for project, task, item, quotation and update records.
-- Does not delete project/task/item/update data and does not modify CER records,
-- editor locks, or PR-release tables. Existing project ownership is assigned to
-- the tracker owner per the single-owner requirement; project member rows are
-- removed to enforce that requirement.
-- Safe to rerun after a partial setup.
-- Target project: igfvoqgeztzmgeebpdgu
-- Tracker owner UID: df8689de-d769-43b9-b2a0-217999468d0b
--
-- Apply order: base tables/security, compatibility repair, item procurement,
-- budget fields, schedule fields and single-owner permissions.


-- ================================================================
-- SOURCE MIGRATION: special-project-management.sql
-- ================================================================

-- Special Project Management for TSD CER Tracker
-- Additive only: does not alter cer_records, editor_lock, or PR-release objects.
-- Review this file before running it in Supabase SQL Editor.

create schema if not exists spm_private;
revoke all on schema spm_private from public, anon;
grant usage on schema spm_private to authenticated;

create table if not exists public.special_projects (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(trim(title)) between 1 and 160),
  description text,
  owner_uid uuid not null references auth.users(id) on delete restrict default auth.uid(),
  status text not null default 'active' check (status in ('active','on_hold','completed','cancelled')),
  priority text not null default 'medium' check (priority in ('low','medium','high','urgent')),
  start_date date,
  due_date date,
  progress integer not null default 0 check (progress between 0 and 100),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (due_date is null or start_date is null or due_date >= start_date)
);

create table if not exists public.special_project_members (
  project_id uuid not null references public.special_projects(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'contributor' check (role in ('manager','contributor','viewer')),
  added_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  primary key (project_id,user_id)
);

create table if not exists public.special_project_tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.special_projects(id) on delete cascade,
  title text not null check (length(trim(title)) between 1 and 180),
  description text,
  assignee_uid uuid references auth.users(id) on delete set null,
  status text not null default 'todo' check (status in ('todo','in_progress','blocked','done')),
  priority text not null default 'medium' check (priority in ('low','medium','high','urgent')),
  start_date date,
  due_date date,
  progress integer not null default 0 check (progress between 0 and 100),
  dependency_ids uuid[] not null default '{}',
  sort_order integer not null default 0,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (due_date is null or start_date is null or due_date >= start_date)
);

create table if not exists public.special_project_milestones (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.special_projects(id) on delete cascade,
  title text not null check (length(trim(title)) between 1 and 180),
  target_date date,
  status text not null default 'pending' check (status in ('pending','in_progress','completed','blocked')),
  responsible_uid uuid references auth.users(id) on delete set null,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.special_project_updates (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.special_projects(id) on delete cascade,
  task_id uuid references public.special_project_tasks(id) on delete set null,
  update_type text not null default 'comment' check (update_type in ('comment','progress','decision','risk')),
  body text not null check (length(trim(body)) between 1 and 8000),
  author_uid uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now()
);

create index if not exists sp_projects_owner_updated_idx on public.special_projects(owner_uid,updated_at desc);
create index if not exists sp_members_user_project_idx on public.special_project_members(user_id,project_id);
create index if not exists sp_tasks_project_order_idx on public.special_project_tasks(project_id,sort_order,created_at);
create index if not exists sp_tasks_assignee_idx on public.special_project_tasks(assignee_uid);
create index if not exists sp_milestones_project_date_idx on public.special_project_milestones(project_id,target_date);
create index if not exists sp_updates_project_created_idx on public.special_project_updates(project_id,created_at desc);

create or replace function spm_private.role_for(p_project uuid)
returns text
language sql stable security definer
set search_path = ''
as $$
  select case
    when exists (select 1 from public.special_projects p where p.id=p_project and p.owner_uid=auth.uid()) then 'owner'
    else (select m.role from public.special_project_members m where m.project_id=p_project and m.user_id=auth.uid())
  end
$$;

create or replace function spm_private.can_read(p_project uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select coalesce(spm_private.role_for(p_project) is not null,false)
$$;

create or replace function spm_private.can_manage(p_project uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select coalesce(spm_private.role_for(p_project) in ('owner','manager'),false)
$$;

revoke all on function spm_private.role_for(uuid) from public, anon;
revoke all on function spm_private.can_read(uuid) from public, anon;
revoke all on function spm_private.can_manage(uuid) from public, anon;
grant execute on function spm_private.role_for(uuid) to authenticated;
grant execute on function spm_private.can_read(uuid) to authenticated;
grant execute on function spm_private.can_manage(uuid) to authenticated;

create or replace function spm_private.guard_project_owner()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.owner_uid is distinct from old.owner_uid then
    raise exception 'Project ownership cannot be changed through this interface';
  end if;
  if new.id is distinct from old.id or new.created_at is distinct from old.created_at then
    raise exception 'Project identity fields are immutable';
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function spm_private.guard_project_owner() from public, anon, authenticated;

drop trigger if exists spm_project_owner_guard on public.special_projects;
create trigger spm_project_owner_guard before update on public.special_projects
for each row execute function spm_private.guard_project_owner();

create or replace function spm_private.guard_task_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_role text;
begin
  if new.id is distinct from old.id
     or new.project_id is distinct from old.project_id
     or new.created_by is distinct from old.created_by
     or new.created_at is distinct from old.created_at then
    raise exception 'Task identity and project fields are immutable';
  end if;
  v_role := spm_private.role_for(old.project_id);
  if v_role in ('owner','manager') then
    null;
  elsif v_role = 'contributor' and old.assignee_uid = auth.uid() then
    if new.title is distinct from old.title
      or new.description is distinct from old.description
      or new.assignee_uid is distinct from old.assignee_uid
      or new.priority is distinct from old.priority
      or new.start_date is distinct from old.start_date
      or new.due_date is distinct from old.due_date
      or new.dependency_ids is distinct from old.dependency_ids
      or new.sort_order is distinct from old.sort_order then
      raise exception 'Contributors may update status and progress only on their assigned tasks';
    end if;
  else
    raise exception 'You do not have permission to update this task';
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function spm_private.guard_task_update() from public, anon, authenticated;
drop trigger if exists spm_task_update_guard on public.special_project_tasks;
create trigger spm_task_update_guard before update on public.special_project_tasks
for each row execute function spm_private.guard_task_update();

create or replace function spm_private.guard_milestone_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.id is distinct from old.id or new.project_id is distinct from old.project_id
    or new.created_by is distinct from old.created_by or new.created_at is distinct from old.created_at then
    raise exception 'Milestone identity and project fields are immutable';
  end if;
  if new.responsible_uid is not null
    and not exists (select 1 from public.special_project_members m where m.project_id=old.project_id and m.user_id=new.responsible_uid)
    and not exists (select 1 from public.special_projects p where p.id=old.project_id and p.owner_uid=new.responsible_uid) then
    raise exception 'Responsible person must belong to this project';
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function spm_private.guard_milestone_update() from public, anon, authenticated;
drop trigger if exists spm_milestone_update_guard on public.special_project_milestones;
create trigger spm_milestone_update_guard before update on public.special_project_milestones
for each row execute function spm_private.guard_milestone_update();

create or replace function spm_private.validate_milestone_responsible()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.responsible_uid is not null
    and not exists (select 1 from public.special_project_members m where m.project_id=new.project_id and m.user_id=new.responsible_uid)
    and not exists (select 1 from public.special_projects p where p.id=new.project_id and p.owner_uid=new.responsible_uid) then
    raise exception 'Responsible person must belong to this project';
  end if;
  return new;
end $$;
revoke all on function spm_private.validate_milestone_responsible() from public, anon, authenticated;
drop trigger if exists spm_milestone_responsible_guard on public.special_project_milestones;
create trigger spm_milestone_responsible_guard before insert or update on public.special_project_milestones
for each row execute function spm_private.validate_milestone_responsible();

create or replace function spm_private.validate_task_links()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_dep uuid;
begin
  if new.assignee_uid is not null
    and not exists (select 1 from public.special_project_members m where m.project_id=new.project_id and m.user_id=new.assignee_uid)
    and not exists (select 1 from public.special_projects p where p.id=new.project_id and p.owner_uid=new.assignee_uid) then
    raise exception 'Assignee must be the project owner or a project member';
  end if;
  foreach v_dep in array new.dependency_ids loop
    if v_dep = new.id then raise exception 'A task cannot depend on itself'; end if;
    if not exists (select 1 from public.special_project_tasks t where t.id=v_dep and t.project_id=new.project_id) then
      raise exception 'Task dependencies must refer to tasks in the same project';
    end if;
  end loop;
  return new;
end $$;
revoke all on function spm_private.validate_task_links() from public, anon, authenticated;
drop trigger if exists spm_task_links_guard on public.special_project_tasks;
create trigger spm_task_links_guard before insert or update on public.special_project_tasks
for each row execute function spm_private.validate_task_links();

-- Keep the project-level progress summary synchronized with task completion.
create or replace function spm_private.refresh_project_progress()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_project_id uuid;
begin
  v_project_id := coalesce(new.project_id, old.project_id);
  update public.special_projects p
  set progress = coalesce((
    select round(100.0 * count(*) filter (where t.status = 'done') / nullif(count(*), 0))::integer
    from public.special_project_tasks t
    where t.project_id = v_project_id
  ), 0),
  updated_at = now()
  where p.id = v_project_id;

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end
$$;
revoke all on function spm_private.refresh_project_progress() from public, anon, authenticated;
drop trigger if exists spm_refresh_project_progress on public.special_project_tasks;
create trigger spm_refresh_project_progress
after insert or update or delete on public.special_project_tasks
for each row execute function spm_private.refresh_project_progress();

create or replace function spm_private.validate_member_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_role text;
begin
  v_role := spm_private.role_for(coalesce(new.project_id,old.project_id));
  if tg_op='INSERT' then
    if exists(select 1 from public.special_projects p where p.id=new.project_id and p.owner_uid=new.user_id) then
      raise exception 'Project owner does not need a membership row';
    end if;
    if v_role='manager' and new.role='manager' then
      raise exception 'Managers cannot promote members to manager';
    end if;
  end if;
  if tg_op='UPDATE' then raise exception 'Membership changes must be made by removing and re-adding a member'; end if;
  return new;
end $$;
revoke all on function spm_private.validate_member_change() from public, anon, authenticated;
drop trigger if exists spm_member_guard on public.special_project_members;
create trigger spm_member_guard before insert or update on public.special_project_members
for each row execute function spm_private.validate_member_change();

alter table public.special_projects enable row level security;
alter table public.special_project_members enable row level security;
alter table public.special_project_tasks enable row level security;
alter table public.special_project_milestones enable row level security;
alter table public.special_project_updates enable row level security;

revoke all on public.special_projects, public.special_project_members, public.special_project_tasks,
  public.special_project_milestones, public.special_project_updates from anon, public;
grant select,insert,update,delete on public.special_projects to authenticated;
grant select,insert,delete on public.special_project_members to authenticated;
grant select,insert,update,delete on public.special_project_tasks to authenticated;
grant select,insert,update,delete on public.special_project_milestones to authenticated;
grant select,insert on public.special_project_updates to authenticated;

drop policy if exists sp_projects_read on public.special_projects;
create policy sp_projects_read on public.special_projects for select to authenticated
using (spm_private.can_read(id));
drop policy if exists sp_projects_create on public.special_projects;
create policy sp_projects_create on public.special_projects for insert to authenticated
with check (owner_uid=auth.uid());
drop policy if exists sp_projects_update on public.special_projects;
create policy sp_projects_update on public.special_projects for update to authenticated
using (spm_private.can_manage(id)) with check (spm_private.can_manage(id));
drop policy if exists sp_projects_delete on public.special_projects;
create policy sp_projects_delete on public.special_projects for delete to authenticated
using (owner_uid=auth.uid());

drop policy if exists sp_members_read on public.special_project_members;
create policy sp_members_read on public.special_project_members for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_members_add on public.special_project_members;
create policy sp_members_add on public.special_project_members for insert to authenticated
with check (
  user_id <> auth.uid()
  and (spm_private.role_for(project_id)='owner'
    or (spm_private.role_for(project_id)='manager' and role in ('contributor','viewer')))
  and added_by=auth.uid()
);
drop policy if exists sp_members_remove on public.special_project_members;
create policy sp_members_remove on public.special_project_members for delete to authenticated
using (
  spm_private.role_for(project_id)='owner'
  or (spm_private.role_for(project_id)='manager' and role in ('contributor','viewer'))
);

drop policy if exists sp_tasks_read on public.special_project_tasks;
create policy sp_tasks_read on public.special_project_tasks for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_tasks_add on public.special_project_tasks;
create policy sp_tasks_add on public.special_project_tasks for insert to authenticated
with check (spm_private.can_manage(project_id) and created_by=auth.uid());
drop policy if exists sp_tasks_edit on public.special_project_tasks;
create policy sp_tasks_edit on public.special_project_tasks for update to authenticated
using (spm_private.can_manage(project_id) or (spm_private.role_for(project_id)='contributor' and assignee_uid=auth.uid()))
with check (spm_private.can_manage(project_id) or (spm_private.role_for(project_id)='contributor' and assignee_uid=auth.uid()));
drop policy if exists sp_tasks_remove on public.special_project_tasks;
create policy sp_tasks_remove on public.special_project_tasks for delete to authenticated
using (spm_private.can_manage(project_id));

drop policy if exists sp_milestones_read on public.special_project_milestones;
create policy sp_milestones_read on public.special_project_milestones for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_milestones_add on public.special_project_milestones;
create policy sp_milestones_add on public.special_project_milestones for insert to authenticated
with check (spm_private.can_manage(project_id) and created_by=auth.uid());
drop policy if exists sp_milestones_edit on public.special_project_milestones;
create policy sp_milestones_edit on public.special_project_milestones for update to authenticated
using (spm_private.can_manage(project_id)) with check (spm_private.can_manage(project_id));
drop policy if exists sp_milestones_remove on public.special_project_milestones;
create policy sp_milestones_remove on public.special_project_milestones for delete to authenticated
using (spm_private.can_manage(project_id));

drop policy if exists sp_updates_read on public.special_project_updates;
create policy sp_updates_read on public.special_project_updates for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_updates_add on public.special_project_updates;
create policy sp_updates_add on public.special_project_updates for insert to authenticated
with check (
  spm_private.can_read(project_id)
  and author_uid=auth.uid()
  and (task_id is null or exists (select 1 from public.special_project_tasks t where t.id=task_id and t.project_id=special_project_updates.project_id))
);
-- No UPDATE or DELETE grants/policies for updates: activity is append-only.

comment on table public.special_projects is 'Special Project Management projects; additive to CER Tracker.';
comment on table public.special_project_members is 'Project membership and roles for Special Project Management.';
comment on table public.special_project_tasks is 'Project tasks; assigned contributors may update status/progress only.';
comment on table public.special_project_milestones is 'Project milestones.';
comment on table public.special_project_updates is 'Append-only project updates and comments.';

-- Read-only verification after applying:
-- select table_name from information_schema.tables where table_schema='public' and table_name like 'special_project_%' order by table_name;
-- select tablename, rowsecurity from pg_tables where schemaname='public' and tablename like 'special_project_%' order by tablename;



-- ================================================================
-- SOURCE MIGRATION: special-project-management-repair.sql
-- ================================================================

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



-- ================================================================
-- SOURCE MIGRATION: special-project-management-rls-fix.sql
-- ================================================================

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



-- ================================================================
-- SOURCE MIGRATION: special-project-management-procurement.sql
-- ================================================================

-- Procurement and item-level tracking for Special Project Management.
-- Additive/idempotent. Does not modify CER records, editor locks, or PR-release tables.
-- Run once in Supabase SQL Editor after the base Special Project Management setup.

begin;

create table if not exists public.special_project_items (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.special_projects(id) on delete cascade,
  item_code text,
  item_name text not null check (length(trim(item_name)) between 1 and 180),
  category text,
  specification text,
  quantity numeric(14,3) not null default 1 check (quantity > 0),
  unit text not null default 'pcs',
  estimated_unit_cost numeric(16,2) not null default 0 check (estimated_unit_cost >= 0),
  procurement_status text not null default 'planned' check (procurement_status in ('planned','rfq','quotes_received','evaluation','approval_pending','approved','po_issued','part_received','received','cancelled_item')),
  supplier_name text,
  supplier_contact text,
  purchase_request_no text,
  approval_status text not null default 'not_started' check (approval_status in ('not_started','pending','approved','rejected')),
  approval_reference text,
  approval_date date,
  po_number text,
  po_date date,
  expected_delivery_date date,
  actual_delivery_date date,
  received_quantity numeric(14,3) not null default 0 check (received_quantity >= 0),
  installation_status text not null default 'not_started' check (installation_status in ('not_started','scheduled','in_progress','installed')),
  testing_status text not null default 'not_started' check (testing_status in ('not_started','scheduled','in_progress','tested','accepted','blocked')),
  installation_date date,
  warranty_until date,
  notes text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (received_quantity <= quantity)
);

create table if not exists public.special_project_item_quotes (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.special_projects(id) on delete cascade,
  item_id uuid not null references public.special_project_items(id) on delete cascade,
  supplier_name text not null check (length(trim(supplier_name)) between 1 and 180),
  quote_reference text,
  quoted_unit_price numeric(16,2) not null check (quoted_unit_price >= 0),
  currency text not null default 'BDT',
  delivery_days integer check (delivery_days is null or delivery_days >= 0),
  quote_date date,
  payment_terms text,
  technical_compliance text not null default 'pending' check (technical_compliance in ('pending','compliant','deviation')),
  is_selected boolean not null default false,
  notes text,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now()
);


create or replace function spm_private.validate_item_quote_link()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if not exists (
    select 1 from public.special_project_items i
    where i.id = new.item_id and i.project_id = new.project_id
  ) then
    raise exception 'Quotation item must belong to the same project';
  end if;
  if tg_op = 'UPDATE' and new.id is distinct from old.id then
    raise exception 'Quotation identity is immutable';
  end if;
  return new;
end
$function$;
revoke all on function spm_private.validate_item_quote_link() from public, anon, authenticated;
drop trigger if exists spm_item_quote_link_guard on public.special_project_item_quotes;
create trigger spm_item_quote_link_guard
before insert or update on public.special_project_item_quotes
for each row execute function spm_private.validate_item_quote_link();

create index if not exists sp_items_project_created_idx on public.special_project_items(project_id,created_at);
create index if not exists sp_items_status_idx on public.special_project_items(project_id,procurement_status);
create index if not exists sp_quotes_item_price_idx on public.special_project_item_quotes(item_id,quoted_unit_price);

alter table public.special_project_items enable row level security;
alter table public.special_project_item_quotes enable row level security;
revoke all on public.special_project_items, public.special_project_item_quotes from anon, public;
grant select,insert,update,delete on public.special_project_items, public.special_project_item_quotes to authenticated;

drop policy if exists sp_items_read on public.special_project_items;
create policy sp_items_read on public.special_project_items for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_items_add on public.special_project_items;
create policy sp_items_add on public.special_project_items for insert to authenticated
with check (spm_private.can_manage(project_id) and created_by=auth.uid());
drop policy if exists sp_items_edit on public.special_project_items;
create policy sp_items_edit on public.special_project_items for update to authenticated
using (spm_private.can_manage(project_id)) with check (spm_private.can_manage(project_id));
drop policy if exists sp_items_remove on public.special_project_items;
create policy sp_items_remove on public.special_project_items for delete to authenticated
using (spm_private.can_manage(project_id));

drop policy if exists sp_quotes_read on public.special_project_item_quotes;
create policy sp_quotes_read on public.special_project_item_quotes for select to authenticated
using (spm_private.can_read(project_id));
drop policy if exists sp_quotes_add on public.special_project_item_quotes;
create policy sp_quotes_add on public.special_project_item_quotes for insert to authenticated
with check (
  spm_private.can_manage(project_id)
  and created_by=auth.uid()
  and exists (select 1 from public.special_project_items i where i.id=item_id and i.project_id=special_project_item_quotes.project_id)
);
drop policy if exists sp_quotes_edit on public.special_project_item_quotes;
create policy sp_quotes_edit on public.special_project_item_quotes for update to authenticated
using (spm_private.can_manage(project_id)) with check (spm_private.can_manage(project_id));
drop policy if exists sp_quotes_remove on public.special_project_item_quotes;
create policy sp_quotes_remove on public.special_project_item_quotes for delete to authenticated
using (spm_private.can_manage(project_id));

comment on table public.special_project_items is 'Item-by-item procurement, approvals, purchase orders, delivery and commissioning.';
comment on table public.special_project_item_quotes is 'Multiple supplier quotations and preferred vendor selection per project item.';

commit;

select table_name
from information_schema.tables
where table_schema='public'
  and table_name in ('special_project_items','special_project_item_quotes')
order by table_name;



-- ================================================================
-- SOURCE MIGRATION: special-project-management-budget-upgrade.sql
-- ================================================================

-- Add budget and financial tracking fields to Special Project Management.
-- Additive and safe to rerun. Does not modify CER records, editor locks, or PR-release data.
begin;
alter table public.special_projects
  add column if not exists approved_budget numeric(16,2) not null default 0;
alter table public.special_project_items
  add column if not exists po_unit_cost numeric(16,2) not null default 0,
  add column if not exists actual_paid_amount numeric(16,2) not null default 0;
alter table public.special_projects drop constraint if exists special_projects_approved_budget_nonnegative;
alter table public.special_projects add constraint special_projects_approved_budget_nonnegative check (approved_budget >= 0);
alter table public.special_project_items drop constraint if exists special_project_items_po_unit_cost_nonnegative;
alter table public.special_project_items add constraint special_project_items_po_unit_cost_nonnegative check (po_unit_cost >= 0);
alter table public.special_project_items drop constraint if exists special_project_items_paid_nonnegative;
alter table public.special_project_items add constraint special_project_items_paid_nonnegative check (actual_paid_amount >= 0);
commit;
select table_name, column_name
from information_schema.columns
where table_schema='public'
  and ((table_name='special_projects' and column_name='approved_budget')
    or (table_name='special_project_items' and column_name in ('po_unit_cost','actual_paid_amount')))
order by table_name, column_name;



-- ================================================================
-- SOURCE MIGRATION: project-management-schedule-upgrade.sql
-- ================================================================

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
