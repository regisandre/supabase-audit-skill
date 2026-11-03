# Measuring on production without writing

Dev databases are usually a fraction of production: plans, row counts and timings differ. Measure
on production, read-only, as the role the client really uses.

## The read-only bench

A `DO` block that ends with `RAISE EXCEPTION` rolls back everything it did and carries the report
in the error message:

```sql
DO $$
DECLARE
  calls text[] := ARRAY[
    'SELECT public.fn_a(42)::text',
    'SELECT coalesce(json_agg(r)::text, '''') FROM public.fn_b(42) r'];
  q text; i int; t0 timestamptz; ms numeric[]; out text; report text := '';
BEGIN
  PERFORM set_config('request.jwt.claims',
    json_build_object('role', 'authenticated', 'sub', '<a real user uuid>')::text, true);
  SET LOCAL ROLE authenticated;
  FOREACH q IN ARRAY calls LOOP
    EXECUTE q INTO out;                       -- warm-up
    ms := '{}';
    FOR i IN 1..15 LOOP
      t0 := clock_timestamp();
      EXECUTE q INTO out;
      ms := ms || (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric;
    END LOOP;
    report := report || format(E'%s | median %s ms | md5 %s\n', q,
      round((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) FROM unnest(ms) x)::numeric, 3),
      left(md5(out), 8));
  END LOOP;
  RESET ROLE;
  RAISE EXCEPTION E'\n%', report;
END $$;
```

- Run the same script before the migration and after it; compare medians and md5s.
- Pick inputs that matter: the busiest entity, an empty one, a stranger, anon.
- One noisy run happens (a 72 ms reading for a 44 ms call): rerun before concluding.
- An MCP `execute_sql` usually returns only the last statement's result: one statement per call.
- Never use this to run DDL, even rolled back: schema changes go through migrations.

## Same-content proof

- md5 of `string_agg(... ORDER BY ...)` over many inputs (every id of a table, several roles, edge
  cases such as unknown ids and padded strings), before and after.
- For RLS changes: compare the rows each viewer sees under the new policy with the old expression,
  over randomized settings, and count differences (must be 0).
- For a deliberate behavior change (a ranking fix), say so in the log and test the new rule.

## Production-wide numbers

`pg_stat_statements` gives calls, total and mean time per statement since the last reset. Take a
snapshot with a timestamp before the migration and diff after; few calls after means "indicative".
