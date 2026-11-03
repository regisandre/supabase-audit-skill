# Table-driven access tests (pgTAP)

One test per rule; its cases are rows of a table the test loops over, each assertion naming its
case. The test runs on a real project in one transaction that rolls back.

```sql
BEGIN;
SELECT plan(4);

SELECT set_config('test.me', (SELECT id::text FROM auth.users ORDER BY created_at LIMIT 1), true);

-- (case, role, sub, sql, allowed); $1 = the user's id
SELECT set_config('test.cases', jsonb_build_array(
  jsonb_build_array('fn: the user for themselves', 'authenticated', 'me',
    'SELECT public.fn($1::uuid)', true),
  jsonb_build_array('fn: another signed-in user', 'authenticated', 'stranger',
    'SELECT public.fn($1::uuid)', false),
  jsonb_build_array('fn: anon', 'anon', NULL, 'SELECT public.fn($1::uuid)', false),
  jsonb_build_array('fn: service role', 'service_role', NULL, 'SELECT public.fn($1::uuid)', true)
)::text, true);

DO $$
DECLARE c jsonb; ok boolean; res jsonb := '{}';
BEGIN
  FOR c IN SELECT * FROM jsonb_array_elements(current_setting('test.cases')::jsonb) LOOP
    PERFORM set_config('request.jwt.claims', jsonb_strip_nulls(jsonb_build_object('role', c->>1,
      'sub', CASE c->>2 WHEN 'me' THEN current_setting('test.me')
                        WHEN 'stranger' THEN gen_random_uuid()::text END))::text, true);
    EXECUTE format('SET LOCAL ROLE %I', c->>1);
    BEGIN
      EXECUTE c->>3 USING current_setting('test.me');
      ok := true;
    EXCEPTION WHEN insufficient_privilege THEN
      ok := false;
    END;
    RESET ROLE;
    res := res || jsonb_build_object(c->>0, ok = (c->>4)::boolean);
  END LOOP;
  PERFORM set_config('test.res', res::text, true);
END $$;

SELECT ok((current_setting('test.res')::jsonb ->> (c->>0))::boolean, c->>0)
  FROM jsonb_array_elements(current_setting('test.cases')::jsonb) c;

SELECT * FROM finish();
ROLLBACK;
```

Pitfalls:

- `insufficient_privilege` catches both a missing EXECUTE grant and a guard raising `42501`.
- Pick fixtures through the function that resolves effective rights, member and entity in the same
  query: a raw permission row may resolve to no right at all, and the "allowed" case then fails.
- Building the cases with a subquery: wrap as `((SELECT ...) || ...)::text`, or the parser
  complains.
- Add a regression case for a function that calls the guarded ones (it must still answer).
- Watch it fail before the migration: a test that was never red proves nothing.
- Write-path tests (an INSERT policy): give each case its own caller and its own row id. Two
  cases inserting the same id hit the unique key (23505) on the second one, which looks like a
  policy answer but is not. Set `request.jwt.claims` per case inside the loop.
- Run the tests on production too, for the real data, in the same rolled-back transaction with
  made-up uuids. Before a test that writes, list the table's triggers and what they call: table
  writes and pg_net requests vanish with the rollback (pg_net sends only after commit), sequences
  advance, anything external (an HTTP call from a trigger through another extension) does not
  roll back. Afterwards, count the made-up ids to prove nothing was left. Keep the first failing
  run on a dev branch, before the migration exists.
