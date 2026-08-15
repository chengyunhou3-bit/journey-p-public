alter table public.quests
  add column if not exists category text not null default '個人成長';

alter table public.journal_entries
  add column if not exists log_data jsonb;
