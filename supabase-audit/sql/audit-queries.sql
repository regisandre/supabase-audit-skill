-- Read-only detection queries. Run one statement at a time.

-- 1. SECURITY DEFINER functions in exposed schemas that client roles can execute.
SELECT p.oid::regprocedure AS fn,
       has_function_privilege('anon', p.oid, 'EXECUTE') AS anon,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') AS authenticated,
       p.prolang = (SELECT oid FROM pg_language WHERE lanname = 'sql') AS is_sql,
       p.proconfig
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname IN ('public', 'graphql_public')
   AND p.prosecdef
   AND (has_function_privilege('anon', p.oid, 'EXECUTE')
        OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
 ORDER BY 1;

-- 2. Of those, the ones whose body never looks at the caller (candidates for a guard or a revoke).
SELECT p.oid::regprocedure AS fn
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.prosecdef
   AND has_function_privilege('authenticated', p.oid, 'EXECUTE')
   AND p.prosrc !~* '(auth\.uid|auth\.jwt|request\.jwt|current_user_uuid|is_service_role)'
 ORDER BY 1;

-- 3. DEFINER functions that take a user id parameter (check they compare it to the caller).
SELECT p.oid::regprocedure AS fn, p.proargnames
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.prosecdef
   AND EXISTS (SELECT 1 FROM unnest(p.proargnames) a WHERE a ~* 'user')
 ORDER BY 1;

-- 4. RLS policies open to everyone.
SELECT schemaname, tablename, policyname, roles, cmd, qual, with_check
  FROM pg_policies
 WHERE schemaname = 'public' AND (qual = 'true' OR with_check = 'true')
 ORDER BY 2, 3;

-- 5. Tables in public without RLS, or without any grant (new tables are not auto-granted).
SELECT c.relname,
       c.relrowsecurity AS rls,
       has_table_privilege('service_role', c.oid, 'SELECT') AS service_role_select,
       has_table_privilege('authenticated', c.oid, 'SELECT') AS authenticated_select,
       has_table_privilege('anon', c.oid, 'SELECT') AS anon_select
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
 ORDER BY c.relrowsecurity, c.relname;

-- 6. SQL functions that cannot be inlined and re-plan on every call (DEFINER or SET clause).
SELECT p.oid::regprocedure AS fn, p.prosecdef, p.proconfig, p.provolatile
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public'
   AND p.prolang = (SELECT oid FROM pg_language WHERE lanname = 'sql')
   AND (p.prosecdef OR p.proconfig IS NOT NULL)
 ORDER BY 1;

-- 7. Where the time goes (needs pg_stat_statements).
SELECT calls, round(total_exec_time) AS total_ms, round(mean_exec_time::numeric, 2) AS mean_ms,
       left(query, 120) AS query
  FROM extensions.pg_stat_statements
 ORDER BY total_exec_time DESC
 LIMIT 30;

-- 8. pg_net calls that really failed (pg_cron says "succeeded" for them).
SELECT id, status_code, error_msg, created
  FROM net._http_response
 WHERE status_code IS NULL OR status_code >= 400
 ORDER BY created DESC
 LIMIT 50;

-- 9. Secrets visible in function bodies.
SELECT p.oid::regprocedure AS fn
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public'
   AND p.prosrc ~* '(sk_live|sk_test|secret|api[_-]?key|bearer\s+[a-z0-9])'
 ORDER BY 1;

-- 10. Foreign keys with no index on the referencing column (slow deletes and joins).
SELECT c.conrelid::regclass AS tbl, c.conname, pg_get_constraintdef(c.oid) AS def
  FROM pg_constraint c
 WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace
   AND NOT EXISTS (SELECT 1 FROM pg_index i
                    WHERE i.indrelid = c.conrelid
                      AND (i.indkey::int2[])[0:cardinality(c.conkey) - 1] = c.conkey)
 ORDER BY 1, 2;

-- 11. Duplicate indexes (same table, same columns, same predicate).
SELECT indrelid::regclass AS tbl, array_agg(indexrelid::regclass) AS duplicate_indexes
  FROM pg_index
 WHERE indrelid::regclass::text NOT LIKE '%.%'   -- public tables only (search_path default)
 GROUP BY indrelid, indkey, indclass, indpred::text, indexprs::text
HAVING count(*) > 1;

-- 12. Indexes never used since the last stats reset (check the reset date and replicas first).
SELECT s.schemaname, s.relname, s.indexrelname, pg_size_pretty(pg_relation_size(s.indexrelid)) AS size
  FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid
 WHERE s.idx_scan = 0 AND NOT i.indisunique AND NOT i.indisprimary
 ORDER BY pg_relation_size(s.indexrelid) DESC
 LIMIT 50;

-- 13. Several permissive policies for the same role and command (each one is evaluated).
SELECT tablename, cmd, roles, count(*) AS policies
  FROM pg_policies
 WHERE schemaname = 'public' AND permissive = 'PERMISSIVE'
 GROUP BY tablename, cmd, roles
HAVING count(*) > 1
 ORDER BY policies DESC;

-- 14. Policies that call auth.uid() bare (candidates for (SELECT auth.uid())).
SELECT tablename, policyname, cmd
  FROM pg_policies
 WHERE schemaname = 'public'
   AND (coalesce(qual, '') || coalesce(with_check, '')) ~ 'auth\.uid\(\)'
   AND (coalesce(qual, '') || coalesce(with_check, '')) !~ '\(\s*SELECT\s+auth\.uid\(\)'
 ORDER BY 1, 2;

-- 15. Functions using (f(row)).* (f runs once per output column).
SELECT p.oid::regprocedure AS fn
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.prosrc ~ '\)\)\.\*'
 ORDER BY 1;

-- 16. Scheduled jobs and their last result (pg_cron).
SELECT j.jobid, j.jobname, j.schedule, j.active,
       (SELECT d.status FROM cron.job_run_details d
         WHERE d.jobid = j.jobid ORDER BY d.start_time DESC LIMIT 1) AS last_status
  FROM cron.job j
 ORDER BY j.jobid;

-- 17. Columns with credential-like names that client roles can select.
SELECT table_name, column_name, grantee
  FROM information_schema.column_privileges
 WHERE table_schema = 'public' AND grantee IN ('anon', 'authenticated')
   AND privilege_type = 'SELECT'
   AND column_name ~* '(secret|(^|_)token$|password|api_?key|stripe|iban|hmac)'
 ORDER BY 1, 2, 3;
