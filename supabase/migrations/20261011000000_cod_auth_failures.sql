create table if not exists public.cod_auth_failures (
  id bigint generated always as identity primary key,
  ip text not null,
  at timestamptz not null default now()
);
create index if not exists cod_auth_failures_at_idx on public.cod_auth_failures (at);
create index if not exists cod_auth_failures_ip_at_idx on public.cod_auth_failures (ip, at);
-- Only the cod-api edge function (service role) touches this table.
alter table public.cod_auth_failures enable row level security;
