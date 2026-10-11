-- Only the cod-api edge function (service role, bypasses RLS) may access this table.
-- No policies on purpose: the public anon/authenticated roles get no access.
alter table public.cod_pipeline enable row level security;
