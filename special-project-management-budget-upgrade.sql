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
