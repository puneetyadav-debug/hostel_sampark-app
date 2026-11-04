alter table public.grievance
add column if not exists updated_at timestamptz;

update public.grievance
set updated_at = created_at
where updated_at is null;

alter table public.grievance
alter column updated_at set default now();

alter table public.grievance
alter column updated_at set not null;