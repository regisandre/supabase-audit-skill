---
name: supabase-audit
description: Speed up a Supabase backend and harden it, one endpoint at a time - plan caching, inlining, RLS per-row cost, indexes, search, cron and pollers first, then grants, SECURITY DEFINER functions, RLS policies, IDOR in RPCs and Edge Functions, webhooks - fix with migrations, prove the same output and measure before/after on the real database without writing to it. Ships scripts to automate the audit, the benchmark and a CI gate. Use when asked to harden, review, optimize or speed up a Supabase backend, an RPC, an RLS policy or an Edge Function, or when the advisor lints flag DEFINER functions.
---

# Supabase audit: speed first, security second, endpoint by endpoint

The method: inventory every endpoint, then take them one by one. For each one, review its security
strictly, try an optimization, prove the output did not change, measure on the real database
read-only, keep only what is faster (a security fix is kept and its cost is measured), and log a
before/after row.

## Rules that hold for every change

1. **Every change is a migration file**, applied by CI. Never run DDL through an MCP `execute_sql`,
   not even inside a rolled-back transaction. Never edit a migration that exists; fix with a new one.
2. **Grants travel with the object.** A new table in `public` gets no privilege by default on
   current projects: grant it in the same migration, least privilege first, RLS enabled next to it.
   A new function gets an explicit `REVOKE ... FROM PUBLIC, anon, authenticated` and the `GRANT
   EXECUTE` it needs. Symptom of a missing grant: `42501 permission denied`.
3. **Same content.** Before and after must return byte-identical results (md5 of the ordered
   output over many real inputs) unless the change is a deliberate fix, logged as such.
4. **Measured, not guessed.** Median of N warm calls, as the real role, on production data, with
   nothing written (see `references/measuring.md`). Dev data is often too small to show a plan.
5. **Test first** for any access rule: a table-driven pgTAP test that fails before the migration
   and passes after (pattern in `references/testing.md`).

## Workflow

1. **Inventory.** List RPCs (`pg_proc` in exposed schemas), tables with their policies, Edge
   Functions with their `verify_jwt` setting, cron jobs, triggers calling `pg_net`. Rank by
   traffic: `pg_stat_statements` (total time, calls, mean) and the Edge Function logs.
2. **Security pass** per endpoint: run the checks in `references/security.md` and the detection
   queries in `sql/audit-queries.sql`. Edge Functions: `references/edge-functions.md`.
3. **Speed pass** per endpoint: `references/performance.md`.
4. **Fix**: write the test, watch it fail, write the migration, push to a dev branch, check CI
   applied it, run the test, then production.
5. **Measure after** on production with the same script, and log the row: endpoint, before ms,
   after ms, delta %, same content (yes / deliberate fix), security verdict.

## The ten findings that come back on every project

1. `REVOKE ... FROM PUBLIC` does not remove the grants Supabase gives **by name** to `anon` and
   `authenticated`. Revoke from all three by name.
2. A `SECURITY DEFINER` function that authorizes against a **caller-supplied user id** instead of
   `auth.uid()` is open to anyone who learns a manager's id.
3. Server-only DEFINER functions left executable by `anon`/`authenticated` (advisor lints 0028,
   0029). Revoke and grant `service_role` only.
4. A guard written `IF uid <> owner` lets a NULL uid through. Use `IS DISTINCT FROM`, and decide
   explicitly what a session without a JWT (cron, `postgres`) may do.
5. Checking a raw permission row instead of the function that resolves effective rights (plan
   limits, revoked roles) grants more than the product does.
6. RLS `USING (true)` on rows that describe people (follows, attendance, membership).
7. A secret (HMAC key, API token) in a table or a function body that a client role can read.
8. `verify_jwt = true` on an Edge Function only proves "a JWT of this project": the public anon key
   passes. The function must still check the user and their rights on every id it receives.
9. `pg_net` is asynchronous: pg_cron logs a job as succeeded even when the HTTP call fails. Read
   `net._http_response` to see the real status.
10. A `LANGUAGE sql` function with `SECURITY DEFINER` or a `SET` clause is never inlined and
    re-plans on every call. For a small hot function, plpgsql (which caches its plan per session)
    is often several times faster.

## Automation

Everything below is read-only and safe to run on production with a read-only role.

| Script | What it does |
| --- | --- |
| `scripts/audit.sh` | Runs `sql/audit-queries.sql` (17 detection queries) in a read-only session and saves one report. |
| `scripts/bench.sh` | Median ms and md5 of a list of SQL calls as a real role (`anon`, `authenticated`), rolled back. Run before and after a migration. |
| `scripts/gate.sh` | CI gate: fails when client-executable DEFINER functions, open policies or RLS-less tables grow past a committed baseline. |
| `sql/rls-plan-scan.sql` | Lists every RLS table whose root filter calls the caller per row (EXPLAIN only, rolled back). |
| `templates/supabase-audit.yml` | GitHub Actions: weekly detection run and gate, pgTAP access tests on pull requests. |

Needs `psql` and a `DATABASE_URL`. Start the loop with `audit.sh`, run `rls-plan-scan.sql` once per
role, rank by `pg_stat_statements`, then fix, bench, log.

## References

- `references/security.md`: grants, DEFINER functions, guards, RLS, secrets, enumeration.
- `references/performance.md`: plan caching, inlining, indexes, search, RLS cost.
- `references/measuring.md`: read-only production benchmarks as the real role, same-content proof.
- `references/testing.md`: table-driven pgTAP access tests.
- `references/edge-functions.md`: auth models, webhooks, IDOR, SSRF, secrets in logs.
- `sql/audit-queries.sql`: 17 detection queries to run read-only (security, indexes, policies, cron).
