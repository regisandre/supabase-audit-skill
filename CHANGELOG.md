# Changelog

> Status: live
> Last checked: 2026-11-03

## 2026-11-03

- Automation: `scripts/audit.sh`, `scripts/bench.sh`, `scripts/gate.sh`, `sql/rls-plan-scan.sql`,
  a GitHub Actions template, and detection queries 10 to 17 (unindexed foreign keys, duplicate and
  unused indexes, stacked permissive policies, bare `auth.uid()`, `(f(row)).*`, cron jobs,
  credential-like columns). Skill description now leads with speed, security second.

- Performance: scan every RLS table's plan for per-row caller helpers, not only the lint's list;
  replace a per-row page check with a once-per-statement set helper that keeps the check as the
  final filter.
- Schema: a duplicate unique key that foreign keys are bound to; capture their definitions,
  drop them, drop the duplicate, re-add them (they bind to the pkey), in one migration with a
  lock timeout.

## 2026-11-02

- Performance: wrap every caller helper of a policy the initplan lint flags, not only `auth.uid()`;
  a DEFINER email helper re-read the users table per row. Check the root `Filter:` in EXPLAIN.
- DEFINER guards: a create or update RPC that copies a jsonb payload runs past the UPDATE
  policies that pin server-owned columns (a verified badge, a payout account); drop those keys for
  clients and pin them in the INSERT policy too.
- Secrets: closing a column to anon on a live table; find every `select=*` caller in a week of
  edge logs first (publishable and secret keys log an empty role), then replay the real shapes.
- RLS: an UPDATE pin that subqueries its own table needs the caller to read the column, and
  breaks with `42P17` once the table's SELECT policy holds a sublink; pin server-owned columns
  with a BEFORE trigger on `current_user` instead, then close the column to signed-in clients.
- RLS: a link table the item owns needs the item right in INSERT and UPDATE; a page-side `OR`
  plus a trigger that copies the page's payout account let a page become an item's payee.
- Grants: server-only tables lose their client grants too (RLS alone answers an outside script
  with `201` or `200 []`), with their sequence, invoker views and helpers.
- Grants: an INVOKER trigger that writes a server-only table blocks its revoke only if clients
  can write the trigger table; inside DEFINER callers it runs as the owner.

- RLS: a link table written from one side is not proof of membership (a draft opened to linked
  pages' teams). Speed: a set-returning DEFINER helper in a policy, plpgsql with one index per
  path, read as `= ANY (ARRAY(SELECT f()))` instead of a hashed `IN` (8.5 -> 1.4 ms).

- Server routes: one owner out of a many-to-many decided by one SQL function (`LIMIT 1` without
  `ORDER BY`, "first with a payment account" and "any linked parent" were three rules for one
  wallet).
- Column grants: revoking one more column of a table that is already granted column by column
  breaks no `select=*` (it already failed); moving a table from a table-level grant to column grants
  breaks every `select=*` client. A body id that sets priority from a tenant's plan, and edit routes
  that skip the create route's child check. Tests: one caller and one row id per write case; run
  access tests on production in a rolled-back transaction after checking the triggers.
- RLS: an `OR` in a WITH CHECK that makes the caller check optional (a profile insert for any id).

- `force_generic_plan` to skip planning: measure with `PREPARE`/`EXECUTE` while alternating roles
  as the API does; a role switch rebuilds RLS plans and erased a single-role gain.
- DEFINER `SETOF table` functions that leak column-granted columns; a normalizer in a filter
  (index the immutable expression); visitor rankings with one count per row.
- Security: `!=` guards that let a NULL caller through; author-only `FOR ALL` policies on rows that
  target another tenant; public "internal" lists and user searches that enumerate emails; a new
  section on server routes on the service role (two ids one check, tenant ids from the body,
  payment account binding by provider metadata).
- Speed: per-row array containment `EXISTS` replaced by one unnested hashed set; pg_cron jobs start
  cold; app pollers replicated across cluster workers.
- Set-returning helpers used only by DEFINER callers: INVOKER without `SET` so they inline.
- `(f(row)).*` runs `f` once per column: use `CROSS JOIN LATERAL`.
- Non-inlined SQL functions keep generic plans whatever `plan_cache_mode` says (plpgsql plus
  `force_custom_plan`); inlined scalar CTEs re-run per row (`AS MATERIALIZED`); DEFINER feeds about
  other people must apply those people's privacy.
- Look for copies of a fixed pattern in sibling functions; floor `EXP` decay arguments (underflow
  on a small radius); quotas in `auth.uid()` triggers skipped by service-role writers; PATCH
  whitelists that move the anchors a create route checks.
- Caller checks on a parameter: per-row calls, initplans hiding the value from the planner, a
  single gate on the final filter instead; `NULLIF` is not a function. Set-returning DEFINER SQL
  feeds that plan longer than they run, moved to plpgsql `RETURN QUERY`.
- Column-level grants for credential columns (RLS selects rows, not columns), UPDATE policies
  that let a row's own user re-enable it, read paths that skip the write path's scope check,
  passing only `P0001` messages to clients, and pg_net's 5 s default timeout on long cron calls.
- First version: method, grants, SECURITY DEFINER guards, RLS, secrets, enumeration, plan caching,
  inlining, search indexes, read-only production bench, pgTAP access tests, Edge Function checks,
  detection queries.
- Edge Functions: a storage delete endpoint that checks only "signed in" lets any account delete
  any object (object paths are public in asset URLs); a server-side fetch of a URL from the body
  without a host allow-list is SSRF; a "resolve or create" endpoint without page rights lets any
  account create and overwrite catalogue rows; an upload endpoint that authorizes one folder
  pattern and accepts any other folder.
- Payments: client quantities (negative lines reaching a free-order branch), `stock - qty`
  with negative or NULL quantities, diffing validation across entry points, binding webhook
  metadata to the account and amount.
- Fixes that need a second look (URL-normalised dot segments, attacker-written ownership rows,
  truncated lists, metadata bindings on unvalidated lines), device session tokens, `auth.uid()`
  on service-role clients, idempotent replays, public lookups.
