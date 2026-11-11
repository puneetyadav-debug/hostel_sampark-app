alter table public.grievance
add column if not exists category text;

insert into public.app_settings (key, value)
values (
    'categories',
    'Plumbing, Electrical, Internet, Mess, Furniture, Cleanliness, Pest Control, Security, Fees, Interpersonal, Ragging, Others'
)
on conflict (key) do nothing;
