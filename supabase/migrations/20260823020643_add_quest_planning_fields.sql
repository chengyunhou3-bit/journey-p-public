alter table public.quests
  add column if not exists duration_minutes integer not null default 0
    check (duration_minutes between 0 and 100000),
  add column if not exists importance integer not null default 3
    check (importance between 1 and 5),
  add column if not exists stamina_recovery integer not null default 0
    check (stamina_recovery between 0 and 999),
  add column if not exists focus_recovery integer not null default 0
    check (focus_recovery between 0 and 999),
  add column if not exists willpower_recovery integer not null default 0
    check (willpower_recovery between 0 and 999);