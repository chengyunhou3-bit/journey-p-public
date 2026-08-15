create table if not exists public.gmail_connections (
  user_id uuid primary key references auth.users(id) on delete cascade,
  refresh_token_ciphertext text not null,
  refresh_token_iv text not null,
  access_token_ciphertext text,
  access_token_iv text,
  access_token_expires_at timestamptz,
  gmail_email text,
  scopes text[] not null default '{}'::text[],
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.gmail_connections is
  'Encrypted Google OAuth tokens; service-role access only.';

alter table public.gmail_connections enable row level security;
revoke all on table public.gmail_connections from public, anon, authenticated;
grant select, insert, update, delete on table public.gmail_connections to service_role;

create policy gmail_connections_no_client_access
on public.gmail_connections
for all
to anon, authenticated
using (false)
with check (false);
