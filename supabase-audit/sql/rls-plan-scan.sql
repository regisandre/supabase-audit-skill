-- Per-row caller helpers in RLS, found from the plans instead of from the lint.
-- Read-only: it runs EXPLAIN only and ends by raising the report, so nothing is kept.
-- Run it once as each role you care about by editing the two lines marked (role) and (sub).
-- A root "Filter:" that calls auth.uid(), a current_user_*() helper, a feature or page check or
-- an inlined current_setting('request.jwt...') is evaluated for every row the scan reads.
-- Wrap the call as (SELECT f()) or move it behind a once-per-statement set helper.
DO $$
DECLARE
  t record; line text; plan text; report text := '';
BEGIN
  PERFORM set_config('request.jwt.claims',
    json_build_object('role', 'authenticated', 'sub', gen_random_uuid())::text, true); -- (sub)
  SET LOCAL ROLE authenticated;                                                         -- (role)
  FOR t IN
    SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname) AS rel
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relrowsecurity
       AND has_table_privilege(c.oid, 'SELECT')
     ORDER BY 1
  LOOP
    plan := '';
    BEGIN
      FOR line IN EXECUTE 'EXPLAIN (COSTS OFF) SELECT * FROM ' || t.rel LOOP
        plan := plan || line || E'\n';
      END LOOP;
    EXCEPTION WHEN OTHERS THEN
      CONTINUE;  -- a table the role may not read through a view or column grants
    END;
    IF plan ~ E'^[^\n]*\n  Filter: [^\n]*(auth\.uid\(\)|current_user_[a-z_]+\(\)|current_setting\(''request\.jwt|[a-z_]*(has_feature|is_admin|is_member)[a-z_]*\()' THEN
      report := report || t.rel || E'\n';
    END IF;
  END LOOP;
  RESET ROLE;
  RAISE EXCEPTION E'tables whose root filter calls the caller per row:\n%', report;
END $$;
