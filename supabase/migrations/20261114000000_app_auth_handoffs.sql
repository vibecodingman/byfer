-- One-time, short-lived credentials used only for website -> Android app sign-in.
create table if not exists public.app_auth_handoffs (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  token_hash text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists app_auth_handoffs_expires_at_idx
  on public.app_auth_handoffs (expires_at);

alter table public.app_auth_handoffs enable row level security;
revoke all on table public.app_auth_handoffs from anon, authenticated;
grant all on table public.app_auth_handoffs to service_role;

-- Remove expired/consumed rows periodically if pg_cron is enabled in the project.
-- Safe to run manually as well:
-- delete from public.app_auth_handoffs
-- where expires_at < now() - interval '1 day'
--    or consumed_at < now() - interval '1 day';
