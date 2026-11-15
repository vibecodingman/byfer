-- Enable username + password sign-in without creating a second Supabase account.
alter table public.profiles
  add column if not exists password_login_enabled boolean not null default false;
