create table if not exists public.calendar_states (
  user_id uuid primary key references auth.users(id) on delete cascade default auth.uid(),
  state jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint calendar_states_state_is_object check (jsonb_typeof(state) = 'object')
);

alter table public.calendar_states enable row level security;

revoke all on table public.calendar_states from anon;
revoke all on table public.calendar_states from authenticated;
grant select, insert, update, delete on table public.calendar_states to authenticated;

drop policy if exists "players_select_own_calendar" on public.calendar_states;
create policy "players_select_own_calendar"
  on public.calendar_states
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "players_insert_own_calendar" on public.calendar_states;
create policy "players_insert_own_calendar"
  on public.calendar_states
  for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "players_update_own_calendar" on public.calendar_states;
create policy "players_update_own_calendar"
  on public.calendar_states
  for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists "players_delete_own_calendar" on public.calendar_states;
create policy "players_delete_own_calendar"
  on public.calendar_states
  for delete
  to authenticated
  using ((select auth.uid()) = user_id);

comment on table public.calendar_states is
  'Per-user Journey P calendar state. RLS restricts each row to its owner.';
