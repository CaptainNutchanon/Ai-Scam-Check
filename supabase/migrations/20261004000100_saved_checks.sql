-- Apply once to the Supabase project used only for this app's shared history.
begin;
create table public.checks (
    id uuid primary key default gen_random_uuid(),
    job_id text not null unique,
    analyzed_at timestamptz not null,
    saved_at timestamptz not null default now(),
    source_type text not null check (source_type in ('text', 'image')),
    input_text text not null check (char_length(input_text) between 1 and 4000),
    risk_level text not null check (risk_level in ('ต่ำ', 'ปานกลาง', 'สูง', 'ไม่สามารถประเมินได้')),
    risk_score integer check (risk_score between 0 and 100),
    analysis_status text not null check (analysis_status in ('complete', 'partial', 'unavailable')),
    is_starred boolean not null default false,
    report_version integer not null check (report_version >= 1),
    report_json jsonb not null check (jsonb_typeof(report_json) = 'object')
);
create index checks_analyzed_at_idx on public.checks (analyzed_at desc, id desc);
create index checks_risk_level_idx on public.checks (risk_level, analyzed_at desc);
create index checks_starred_idx on public.checks (analyzed_at desc) where is_starred;
alter table public.checks enable row level security;
revoke all on public.checks from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on public.checks to service_role;
create function public.search_checks(
    p_page integer default 1, p_query text default '', p_level text default '',
    p_starred boolean default false, p_start timestamptz default null, p_end timestamptz default null
) returns jsonb language plpgsql security invoker set search_path = '' as $$
declare result jsonb;
begin
    if p_page is null or p_page < 1 or p_page > 100000 or p_query is null
       or char_length(p_query) > 200 or p_level is null
       or p_level not in ('', 'ต่ำ', 'ปานกลาง', 'สูง', 'ไม่สามารถประเมินได้')
       or (p_start is not null and p_end is not null and p_start >= p_end) then
        raise exception 'Invalid history filters';
    end if;
    with matched as materialized (
        select id, analyzed_at, saved_at, source_type, left(input_text, 180) as input_text,
               risk_level, risk_score, analysis_status, is_starred, report_version
        from public.checks
        where (p_query = '' or strpos(lower(input_text), lower(p_query)) > 0)
          and (p_level = '' or risk_level = p_level)
          and (not p_starred or is_starred)
          and (p_start is null or analyzed_at >= p_start)
          and (p_end is null or analyzed_at < p_end)
    ), paged as (
        select * from matched order by analyzed_at desc, id desc
        limit 20 offset (p_page - 1) * 20
    )
    select jsonb_build_object(
        'items', coalesce((select jsonb_agg(to_jsonb(p) order by p.analyzed_at desc, p.id desc) from paged p), '[]'::jsonb),
        'total', (select count(*) from matched), 'page', p_page, 'page_size', 20
    ) into result;
    return result;
end;
$$;
revoke all on function public.search_checks(integer, text, text, boolean, timestamptz, timestamptz) from public, anon, authenticated;
grant execute on function public.search_checks(integer, text, text, boolean, timestamptz, timestamptz) to service_role;
-- No public RLS policies: a secret key is used ONLY by the local Python backend.
-- service_role bypasses RLS. This schema does not provide per-user ownership.
commit;
