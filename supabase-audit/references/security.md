# Security checks

Each check: what to look for, how to detect it, the fix, the pitfall.

## 1. Grants by name survive `REVOKE FROM PUBLIC`

- **Detect**: `has_function_privilege('anon', oid, 'EXECUTE')` and the same for `authenticated`
  on every function of the exposed schemas (query in `sql/audit-queries.sql`).
- **Fix**:
  ```sql
  REVOKE ALL ON FUNCTION public.fn(int) FROM PUBLIC, anon, authenticated;
  GRANT EXECUTE ON FUNCTION public.fn(int) TO service_role;
  ```
  For a batch, loop over `pg_proc` by name in a `DO` block and `EXECUTE format(...)` with
  `oid::regprocedure`, so every overload is covered.
- **Pitfall**: before revoking, grep every client (app, website, Edge Functions, RLS policies,
  other functions) for the name. An RLS policy that calls the function needs the role to keep
  EXECUTE; in that case guard the body instead.

## 2. Server-only functions

Functions only called by servers, cron or triggers (stats, exports, dispatch lists, deletion
queues, scoring) should be `service_role` only. Write a pgTAP test that lists them and asserts
`anon` and `authenticated` false, `service_role` true, and reports "no such function" for a
renamed one (LEFT JOIN on the list), so the list cannot rot silently.

The same goes for server-only tables (queues, import logs). RLS with no policy for a role hides
every row, but the table grant still lets the call through: an outside script on the public key
gets `201` for an empty batch and `200 []` for a read, and keeps running unnoticed. Revoke the
table, its sequence, the `security_invoker` views over it and its INVOKER helpers from `anon` and
`authenticated`, so such a caller gets `401` and shows up in the logs as refused.

Before keeping a client grant because an INVOKER trigger or helper writes the table, check who
can fire it: a trigger runs as the role that wrote the trigger table, and inside a DEFINER
function that role is the owner. If clients cannot write the trigger table (no INSERT, UPDATE or
DELETE policy for them) and every RPC that reaches the helper is DEFINER, the write never happens
as a client, and the table and the helper can both go to the service role alone.

## 3. Caller-bound guards in SECURITY DEFINER functions

A DEFINER function runs as its owner and bypasses RLS: it must authorize the caller itself.

```sql
IF NOT public.is_service_role()
   AND (auth.uid() IS NULL OR auth.uid() IS DISTINCT FROM p_user_id) THEN
  RAISE EXCEPTION 'fn: not authorized' USING errcode = '42501';
END IF;
```

- `is_service_role()` reads `request.jwt.claims ->> 'role'`. It is **false** for a session with no
  claims (pg_cron, `postgres`, a trigger fired from such a session). Decide on purpose whether
  those sessions pass; if the function must stay callable by anon for an RLS policy, refuse any
  JWT session that names someone else and let sessions with no JWT through.
- For an action on an entity (page, event, order), check the caller's effective rights on that
  entity with the function that resolves them, not a raw permission row.
- Raise `42501` so clients and tests can tell "forbidden" from a bug.
- **NULL slips through `!=`.** `IF current_user_id() != v_owner THEN <deny unless member>` skips
  the whole check for a signed-out caller: `NULL != x` is NULL, and `IF NULL` is false. Write
  `IS DISTINCT FROM`, or refuse a NULL caller first. Detect: `prosrc ~ '(uid|user_uuid)\(\)\s*!='`.
  When only the server calls the function, revoke EXECUTE from clients instead.
- **Shared guard helper**: one `require_member(entity_type, entity_id)` function (plpgsql,
  `SET search_path = ''`, revoked from clients) called with `PERFORM` at the top of each guarded
  function keeps the rule in one place. Measured cost: about 0.07 ms per call.
- **A DEFINER create or update RPC that copies a payload skips column pins.** An UPDATE policy
  that pins `is_verified` or a payout account id holds for direct writes only; a DEFINER
  `update_x(p_id, p_data jsonb)` that maps every key runs past it, so a page manager verifies
  their own page. Drop the server-owned keys for clients (`IF NOT is_service_role() THEN
  p_data := p_data - 'is_verified' - 'payout_account_id'; END IF;`), and pin the same columns in
  the INSERT policy's `WITH CHECK`. Detect: DEFINER bodies that read `p_data->>'<pinned column>'`.
  An insert refused today by a later trigger (one whose own insert hits RLS) is safe by
  accident: test that the error names the table's own policy.
- **Splicing a guard into a long live function** without copying its body (copies drift): in a
  migration `DO` block read `pg_get_functiondef(oid)`, insert the guard after the first
  `\nBEGIN\n` that follows `AS $function$` (plpgsql) or prepend a `SELECT guard(...);` statement
  (SQL), assert the anchor occurs exactly once, then `EXECUTE` the result.

## 4. RLS policies

- `USING (true)` for anon/authenticated on rows about people leaks who follows, attends or belongs
  to what. Rewrite the policy to the owner plus whoever the owner's privacy setting lets in.
- A DEFINER helper called **per row** in a policy costs tens of microseconds a row (each lookup
  inside it re-runs). Compute the exceptions once per query instead: an uncorrelated subquery or a
  function returning the set (an initplan), with the slow check only for rows in that set. Prove
  the same rows with a randomized comparison against the per-row expression.
- A DEFINER feed that shows **other people's** activity to the caller (friends going to an event,
  friends' attendee lists) must apply those people's privacy, not only check the caller: a
  privacy-aware RLS on the underlying table does not protect a function that reads past it. Build
  the visible friends once (`WITH visible AS MATERIALIZED (...)` with the follower rule and blocks
  both ways) and filter on it; test one privacy setting per case against what the RLS shows.
- **A link row is not proof of membership.** Opening a private row (a draft, an unpublished page)
  to "the team of every page linked to it" trusts link tables (`item_owner`, `item_venue`) whose
  INSERT policy checks rights on **one** side only: a manager of any page links it to any item id
  and reads the item. Before a policy follows a link, read the link table's write policy; grant
  through a right on the item itself (or a link both sides approved). Test the linked-page team
  as a case that must fail.
- **The owning side decides a link.** When an item chooses its pages (an event its organisers,
  venue, line-up), the link table's INSERT and UPDATE `WITH CHECK` must require the item right;
  an `OR` with the page right lets any page attach itself, or move its row onto another item with
  an UPDATE of the foreign key. Look for AFTER INSERT triggers on the link that copy money fields
  (a payout account "if the item has none"): a self-link then sets the payee. Keep DELETE on the
  page side so a page can still leave, and check the DEFINER "add" and "set" RPCs too: they often
  test only the page side.
- A helper that lists restricted users belongs in a schema the Data API does not expose.
- Wrap `auth.uid()` as `(select auth.uid())` in policies so it is evaluated once.
- **RLS picks rows, not columns.** A row a user may see is returned with every column, credentials
  included: a device table holding its permanent token (or a token next to its hash) is readable
  by everyone the SELECT policy lets in. Detect: `has_column_privilege('authenticated', tbl, col,
  'SELECT')` on columns named like `*token*`, `*secret*`, `*hash*`, `*_ip`. Fix: `REVOKE SELECT`
  on the table, then `GRANT SELECT (col, ...)` on the public columns (a column-level REVOKE does
  nothing while the table-level grant exists). Check the clients' select lists first.
- **Moving a table to column grants breaks `select=*`.** PostgREST sends `SELECT t.*`, which needs
  every column: clients that ask for `*` get 42501 the moment the table-level grant goes, so the
  first attempt is often reverted and the private columns stay public "for now". Grep the clients
  for `select('*')` and embeds of the table before the switch. Once a table is already granted
  column by column (`has_table_privilege(role, tbl, 'SELECT')` is false), revoking one more column
  breaks nothing that worked, so do it in the same pass: consent flags and account-state columns
  (`*_consent`, `deactivated_at`, `deletion_requested_at`) are typical leftovers readable by anon
  on every profile.
- **`FOR ALL ... USING (created_by = me) WITH CHECK (created_by = me)` checks only the author.**
  On a table whose rows target another tenant (a page, an event, a shop), any signed-in user can
  insert rows for any target: a broadcast row eats that page's monthly quota and fires its
  triggers (alerts to the page's team) with the attacker's text. Detect: write policies whose
  check mentions only the author column on tables with `entity_id` / `event_id` columns. When the
  server writes these rows with the service role, keep an own-row SELECT and revoke the writes.
- **An `OR` in a WITH CHECK can make the caller check optional.** A profile INSERT checked
  `(well-formed username) OR (id = me AND email set)`: the first branch never looked at the id, and
  the profile id had no foreign key to `auth.users`, so any account could create profiles for
  made-up ids or for an auth user that had no profile yet. Detect: write policies with a top-level
  `OR` where only one branch mentions `auth.uid()`. Fix: `id = (select auth.uid()) AND (<old
  check>)`, which keeps every self-insert that passed before; test one caller per case.
- **A policy subquery on its own table fails once that table's SELECT policy holds a sublink.**
  An UPDATE pin `(SELECT t2.col FROM t t2 WHERE t2.id = t.id)` worked for months. Then a new
  SELECT policy on `t` with `id = ANY (ARRAY(SELECT f()))` made every client UPDATE fail with
  `42P17 infinite recursion detected in policy for relation "t"`, while reads kept working.
  Detect: policies whose quals or checks select from their own table. After changing any policy
  on a table, run one real client UPDATE on it. Fix: a BEFORE trigger for pins (see section 5).
- **UPDATE policies that let "the row's own user" through** let that user change any column,
  status included: a disabled device account re-enables itself. If clients never write the
  table, revoke INSERT/UPDATE/DELETE from `authenticated` and `anon` instead of tuning policies.

## 5. Secrets readable by clients

Look for keys in tables, in function bodies (`pg_get_functiondef` is readable by anyone who can see
the function), in `app_settings`-style rows, and in Edge Function responses or logs. Move them to
Vault or a private schema readable by `service_role` only, and rotate them if they were exposed.

A DEFINER function returning `SETOF table` or `SELECT *` hands out every column, including the
ones a column-level grant withholds from `anon` (a payment account id behind a public venue
read). Compare `information_schema.column_privileges` with the function's output; an INVOKER SQL
function with an explicit column list applies the grants and inlines. Returning a column list
(`RETURNS TABLE`) also survives a new column on the table, where a fixed list under
`SETOF table` would fail at run time.

Closing a column to `anon` on a live table (`REVOKE SELECT ... FROM anon; GRANT SELECT (cols) ...`)
breaks every `select=*`, `table(*)` embed, INVOKER `t.*` or `row_to_json(t)` that anon runs.
Before the migration:
- read a week of edge logs for anon requests on the table with no `select=`, a `*`, or the column
  itself, and name each caller (`x-client-info`, IP, schedule); a scheduled job outside the repos
  shows up only there;
- filter on more than `request.sb.jwt.authorization.payload.role = 'anon'`: a call made with a
  `sb_publishable_` or `sb_secret_` key logs an empty role;
- grep for embeds with a hint or alias too (`table!inner(*)`, `alias:table(*)`), not only
  `table(*)`;
- after it is applied, replay the real request shapes with the publishable key and expect 200,
  and 401 `42501` for the closed column and for `select=*`.

Closing it to `authenticated` also breaks the writes when an UPDATE policy pins the column with
a subquery on its own table (`col IS NOT DISTINCT FROM (SELECT t2.col FROM t t2 WHERE t2.id =
t.id)`): that subquery runs as the caller and needs SELECT on the column, so every client save
returns `42501`. Move the pin out of the policy first: a BEFORE INSERT OR UPDATE trigger that,
when `current_user` is `anon` or `authenticated`, puts back `OLD.col` (the default on insert).
The trigger needs no column privilege, and service-role and DEFINER writes skip it. Test it as a
real manager of a real row: a plain save must pass, the server-owned write must leave the value
unchanged, and the read must fail.

## 6. Enumeration

An RPC that answers "does this email / username / phone exist" lets anyone enumerate accounts.
Revoke anon; for signed-in callers, move the check behind a rate-limited server route and revoke
`authenticated` too.

- Lists that look internal are often public: a `blocked_emails`-style table with `USING (true)`
  for anon publishes every address on it. The signup hook is SECURITY DEFINER (or has its own
  grant), so clients need no access at all.
- A "find a user to add" search gated on "manages some page" is open to anyone when anyone can
  create a page. Match usernames by substring, match an email only when typed in full, and
  return the email only for that exact match.

## 7. Account bootstrap functions

A "create my profile row" RPC that takes an auth user id must refuse any id other than the
caller's (service role exempt). Otherwise anyone can create or probe rows for other users.

## 8. Advisor lints

Run the security advisor after each wave: 0028/0029 (DEFINER executable by anon/authenticated),
0011 (`function_search_path_mutable`), RLS disabled, policies `USING (true)`. A lint can conflict
with speed (a `SET search_path` blocks inlining): name objects fully qualified instead of dropping
the `SET`, or accept the cost and write down why.

## 9. Server routes on the service role

A server route on the service role bypasses RLS, so each one must tie every id it takes from the
request to the caller.

- **Two ids in one path, one check.** `/artist/[artistId]/presskits/[id]/assets/[assetId]` with a
  permission check on `artistId` alone acts on any artist's presskit: read the child with
  `.eq('artist_id', artistId)`. A source test over the route folder ("every handler reads the
  parent with the path's owner id") keeps new routes honest.
- **Ids from the body that pick a tenant.** A body `event_id` that decides which organiser owns
  the new row must be checked against the caller, or ignored on surfaces where nothing checks it.
- **Payment account ids.** A route that stores a payment-provider account id on a page (Stripe
  Connect `acct_...`) must prove the account is that page's: tag the account with the page in the
  provider's `metadata` when the server creates it, and accept only the page's current account or
  one tagged for it. Otherwise a page manager binds another page's account and reads its
  dashboard link and balance through the sibling routes.
- **Quotas in triggers keyed on `auth.uid()`.** A trigger that counts creations per user lets a
  session without a user through (service role, cron), so an Edge Function that verifies the JWT
  and then inserts with the service role skips the quota. Move the trigger's body into a
  `consume_quota(user, kind)` granted to `service_role` only; the trigger calls it for
  `auth.uid()`, and each function calls it for the verified user just before its insert (after
  any dedup lookup, so a match costs nothing).
- **A body id that raises priority.** A public support route looked up the plan of a page id from
  the body to set the ticket's priority: anyone could quote a paid page's id to jump the queue.
  Honour a cited tenant only for a signed-in member of it, and return only what the form reads
  (the route returned the whole helpdesk document to anonymous callers).
- **The edit route skips the create route's check.** Creation checked that every child id (the
  items a code unlocks) belonged to the parent; the PATCH stored the list as sent. Put the check
  in one helper both call, and test it with a stub of the table.
- **Update whitelists carry the anchors too.** A create route that checks the parent ids is not
  enough if the PATCH whitelist accepts the same columns: narrow the patch per surface (the parent
  fixed, the owner column untouched, a linked child checked against the caller's scope).
- **One owner out of a many-to-many, decided once.** When a resource belongs to one parent among
  several (the organiser a co-organised event's cashless wallet pays), every path that picks it
  must use the same rule. Look for `... FROM link_table WHERE child_id = $1 LIMIT 1` with no
  `ORDER BY` (physical order, not a rule), "the first one with a payment account", and
  "any linked parent" in a scope check: three rules let one organiser's managers run the other's
  tills and route a charge to an account that is not the one credited. Put the rule in one SQL
  function (the payment payee, else the lowest id), grant it to `service_role`, and make the
  permission check, the validity check, the payment routes and the server routes all call it.
  `grep -rn "link_table" functions/ server/` and `prosrc ILIKE '%link_table%'` find the copies.
