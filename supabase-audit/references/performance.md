# Speed checks

Start from `pg_stat_statements`: sort by total time, not mean. A 0.25 ms call made 2 million
times matters more than a 500 ms call made 30 times.

## 1. SQL function vs plpgsql (plan caching)

- A `LANGUAGE sql` function is inlined into the caller only if it is not `SECURITY DEFINER`, has
  no `SET` clause, is not `STRICT` in a way that blocks it, and its volatility is compatible.
  Otherwise it is a real function call that **parses and plans its body on every call**.
- plpgsql caches the plan of each statement for the session. For a small, hot DEFINER function,
  rewriting `SELECT ...` as `BEGIN RETURN (SELECT ...); END` (or `RETURN QUERY SELECT ...`) gave
  0.24 -> 0.04 ms (-83%) on a typical check, same output.
- It does not help when the cost is the work itself (per-row lookups inside the function): measure
  before assuming re-planning is the cost.
- Migration trick for many functions: a `DO` block that reads each body, asserts it is a single
  `SELECT`, and rewrites it into plpgsql `RETURN (...)`.
- Set-returning feeds too: a DEFINER SQL feed with a few CTEs can spend more time planning than
  running (EXPLAIN: 4 ms planning, 1.4 ms execution). `RETURN QUERY <same query>` in plpgsql took
  one from 2.4 to 0.70 ms and two leaderboards from about 1 ms to 0.4-0.5 ms. Start a
  `RETURNS TABLE` body with `#variable_conflict use_column`, or the output names shadow the
  columns of the same name. Feeds dominated by execution (10+ ms) gain nothing; measure each.

## 2. `SET search_path` and inlining

A `SET search_path` on a function blocks inlining and adds a config switch per call (~5 us). For
an IMMUTABLE wrapper used in indexes (e.g. `unaccent` with a named dictionary), qualify every name
instead of setting the path. Expect the linter to flag it; document the trade-off.

## 3. Generic plans on optional-filter functions

A function with `p_x IS NULL OR col = p_x` branches gets a generic plan that keeps every branch.
`SET plan_cache_mode = force_custom_plan` on the function lets the planner fold the branches away
for each call's real arguments (54 -> 11 ms on a search branch).
A SQL function that is not inlined (SECURITY DEFINER, `SET`, set-returning) plans its body with
the arguments as unknown parameters on every call, so the same branches stay; the setting does not
reach it. Move it to plpgsql `RETURN QUERY` (with `#variable_conflict use_column` for `RETURNS
TABLE`) and set `force_custom_plan` there: a feed went 51 -> 20 ms signed in, 45 -> 7 ms signed out.

Before you switch a fast function to `force_generic_plan` to save planning time, test it the way it
is served. In a read-only transaction, `PREPARE` the body with `$n` arguments. Then `EXECUTE` it
under each `plan_cache_mode`, replacing `random()` with a constant so the rows can be compared.
Switch the role between executions as the API does: an `anon` call, then a signed-in call. A role
change rebuilds a cached plan whose query has RLS, so the generic plan's gain disappears there.
One feed was 18-30% faster with a generic plan in a single-role session and broke even once the
role alternated. The first call of each session also paid 101 ms of generic planning, so the
change was reverted. Sibling feeds were up to 3x slower with a generic plan even in one role.

## 4. Text search

- `unaccent(col) ILIKE '%q%'` cannot use an index (`unaccent` is STABLE). Create an IMMUTABLE
  wrapper, trigram GIN indexes on it, and tsvector GIN indexes; rewrite the filters onto them.
- `word_similarity(q, col) > 0.3` is not indexable; put `q <% col` in front with
  `pg_trgm.word_similarity_threshold` pinned on the function, so the index narrows and the original
  test still decides.
- Queries under 3 characters give a trigram index nothing to narrow and get **slower** with it:
  keep the original filter for them, `((v_trgm AND indexed) OR (NOT v_trgm AND original))`, with a
  custom plan dropping the branch not taken.
- `ANALYZE` after creating expression indexes, or the planner estimates them at 1 row.
- Plain `CREATE INDEX` blocks writes for the build; use `CONCURRENTLY` outside a transaction when
  the table is busy (a migration runs in a transaction, so plan for it).

## 5. Arrays and indexes

Casting an `integer[]` column to `bigint[]` before `&&` keeps its GIN index out of the plan.
Compare with the column's own type.

## 6. Correlated work per row

- `EXISTS` over a large join per candidate row: collect the matching ids once into an array or a
  materialized CTE and use a hashed `IN` / `= ANY`.
- One count subquery per row: one grouped read joined back. A visitor ranking that scored every
  row of a 9,476-row table by its follower count ran 9,476 subqueries for 536 follows: a grouped
  read left-joined back gave the same scores at 46 -> 17 ms.
- A normalizer in a filter (`WHERE normalize_email(u.email) = v`) runs once per row of the table,
  and a PL/pgSQL one costs microseconds each: 1.9 ms for 370 rows, which was the whole cost of an
  upsert called 95k times. If the function is `IMMUTABLE`, index the expression (0.12 ms), and
  `REINDEX` in any migration that changes the function's body.
- `SELECT (f(row)).*` evaluates `f` once per output column, not once per row: a
  `jsonb_populate_record(NULL::t, to_jsonb(x) - hidden_keys())` row filter on a 23-column table ran
  23 times a row (4 ms for one primary-key read, 51 ms for a 33-row search). Use
  `SELECT r.* FROM x CROSS JOIN LATERAL f(x) r` (-91% to -98%), and lift a per-query helper into an
  initplan `(SELECT hidden_keys())`. Detect with `prosrc ~ '\)\)\.\*'`.
- `EXISTS (SELECT 1 FROM t WHERE t.ids @> ARRAY[x.id])` per row cannot use a hash: with no GIN
  index it is a sequential scan of `t` for every candidate (3,403 loops, 1.2 million buffers,
  8 s). `x.id IN (SELECT u FROM t CROSS JOIN LATERAL unnest(t.ids) u)` builds one hashed set
  (38 ms, -99.5%), same rows: a NULL in the set turns a miss into NULL, which `CASE WHEN` and
  `WHERE` treat as false.
- A CTE referenced once is inlined. A scalar aggregate CTE (`n AS (SELECT count(*) ...)`) joined
  with `FROM rows, n` can then be re-run once per row in a nested loop; `AS MATERIALIZED` runs it
  once (36 -> 6 ms). Check the EXPLAIN for loops on the aggregate. Fixed in one function, look for
  its copies: sibling feeds are often cloned, and the same join cost 46 of 73 ms in a sibling that
  nobody had touched (`grep` `pg_get_functiondef` across `pg_proc` for the pattern).
- `EXP(-distance / radius)` style decays raise 22003 (underflow) once the argument passes about
  -745: a small radius and one far-away row fail the whole call. Floor the argument
  (`EXP(GREATEST(x, -700))`); the bonus is about 1e-304 there, so no successful answer changes.
  Probe every scoring function with extreme but legal inputs (tiny and huge radii).
- A DEFINER helper called per row is never inlined; inline its tests when they are simple.
- The `auth_rls_initplan` lint names a policy for its bare `auth.uid()`, but a caller helper
  next to it costs more: `current_user_email()` as SECURITY DEFINER SQL is never inlined, so a
  bare call re-reads `auth.users` for every row the scan filters. Wrap every caller-derived call
  of the flagged policy, not only the one the lint names (a signed-in ticket list over 798 rows:
  28.5 -> 3.0 ms, same md5). Prove it at runtime: as the real role, `EXPLAIN (COSTS OFF)` the
  table read and assert the root node's `Filter:` line holds no `auth.uid()`, no helper call and
  no inlined `current_setting('request.jwt...')`; InitPlans and hashed subplans run once and
  may keep them.
- Do not stop at the lint's list: scan every RLS table. As anon and as a signed-in user,
  `EXPLAIN (COSTS OFF) SELECT * FROM <table>` for each table the role may read, and keep the ones
  whose root `Filter:` calls a caller helper (`current_user_*()`, a page or feature check taking
  the caller id). One pass found 28 tables the lint missed. Fix the ones with real rows; a page
  check per row (`has_feature(me, entity_type, entity_id, 'x')`, plpgsql, three queries) cost
  16 ms on a 119-row list. Replace it with a set helper, DEFINER, run once:
  `(entity_type, entity_id) IN (SELECT * FROM caller_feature_pages('x'))`. List the caller's
  candidate pages from every source the check reads, then keep the check itself as the final
  filter on each candidate, so the visible rows cannot change (16.4 -> 4.1 ms, 9.7 -> 1.0 ms,
  5.6 -> 0.9 ms). A table every role may read needs the helper granted to anon too.
- A set-returning DEFINER helper in a policy (`id IN (SELECT private.visible_ids())`, the ids the
  caller may see past `is_public`) has three costs to measure on a real list query, as the real
  role:
  - as one SQL `UNION` it is replanned on every statement (5 ms of planning in EXPLAIN): plpgsql
    `RETURN QUERY` caches it per connection;
  - an `OR` across buyer paths (`o.user_id = me OR lower(o.email) = my_email`) seq-scans the join:
    one `UNION` branch per path, each on its own index, and fetch the email once into a variable;
  - `IN (SELECT f())` became a hashed subplan that cost 2.5 ms a statement; `= ANY (ARRAY(SELECT
    f()))` is an initplan, still lazy (only when a row reaches that `OR` branch): 3.65 -> 1.41 ms.
  The first version of such a policy took a listing from 0.95 to 8.5 ms; the three steps brought
  it to 1.4 ms. Compare sorted ids, not an unordered `json_agg`: a plan change reorders the rows.
- A set-returning helper that only DEFINER callers use (`list_for(p_user)` filtered and limited
  by each caller) needs neither DEFINER nor `SET`: it runs with the caller's owner rights. As
  INVOKER SQL with schema-qualified names and no `SET` it is inlined, so the caller's `WHERE` and
  `LIMIT` reach the index (a 30-row bell list 5.7 -> 1.1 ms). Keep EXECUTE revoked from clients.
- A caller check on a parameter (`f(p_user)` returning the value or NULL) costs in three ways:
  as a plain call in a filter it runs once per row; wrapped as `(SELECT f(p_user))` it runs once,
  but as an initplan it **hides the parameter's value from the planner**, which then plans for any
  value (0.78 -> 1.52 ms on a leaderboard). Keep the raw parameter in the body and add one gate,
  `AND (SELECT f(p_user)) IS NOT NULL`, when the denied answer is empty (1.52 -> 1.02 ms).
- `NULLIF` is SQL syntax, not a function: `pg_catalog.nullif(...)` fails. Schema-qualify the
  functions in an inlinable body, not the keywords.

## 7. Restrict before you aggregate

Functions that build a whole catalogue and then filter to one entity: find the entity's keys first
and aggregate only those (26 -> 11 ms on the hottest function of a project, 790k calls).

## 8. Know when to stop

- A pg_cron job runs in a new backend each time: plan and catalog caches start cold, so an empty
  poll costs 5 to 20 ms of planning (0.1 ms of execution). Merging jobs shares the warm-up but
  ties their failures together; at a few hundred seconds a day it is rarely worth it.
- An app-server poller replicated across cluster workers multiplies an empty claim by the worker
  count. Poll from the first worker only (`NODE_APP_INSTANCE` 0 under PM2) when one worker can
  drain the queue; the `SKIP LOCKED` lease keeps it safe if more are turned on.

- A call already at the floor (one index probe, 0.25 ms) is fixed by calling it less (back off a
  polling worker), not by SQL.
- Time spent outside Postgres (gateway p50 far above the in-database time) is not a SQL problem.
- Log what was tried and not kept, with numbers, so nobody tries it again.
