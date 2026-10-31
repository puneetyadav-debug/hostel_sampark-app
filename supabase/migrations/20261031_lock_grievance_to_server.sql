alter table public.grievance enable row level security;

revoke all privileges on table public.grievance
from anon, authenticated;