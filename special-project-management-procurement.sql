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
