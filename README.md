# supabase-audit

> Status: live, updated as new lessons come in
> Last checked: 2026-11-03

An agent skill (Claude Code and compatible agents) to speed up and harden a Supabase project
endpoint by endpoint: find slow calls first, then security holes, fix them with migrations, prove
the output did not change, and measure before/after on production without writing to it. It ships
the scripts to automate the audit, the benchmark and a CI gate.

Every check in it came from a real audit of a production Supabase backend (about a thousand RPCs,
ninety Edge Functions). Each one says what to look for, how to detect it, how to fix it, and the
trap that comes with the fix.

## What it covers

| Area | Examples |
| --- | --- |
| Grants | `REVOKE FROM PUBLIC` leaving by-name grants, server-only functions callable by clients, new tables without grants |
| SECURITY DEFINER | caller-supplied user ids, NULL-uid guards, raw permission rows vs resolved rights, splicing a guard into a live function |
| RLS | `USING (true)` on rows about people, per-row helper cost, once-per-query exception lists |
| Secrets and enumeration | keys readable by clients, "does this email exist" RPCs |
| Edge Functions | what `verify_jwt` really proves, webhook signatures, IDOR through a service-role client, SSRF, OAuth state, logs |
| Speed | SQL vs plpgsql plan caching, inlining blockers, generic vs custom plans, trigram and full-text indexes, per-row work |
| Proof | read-only production benchmarks as the real role, md5 same-content checks, table-driven pgTAP access tests |

## Install

Copy the `supabase-audit` folder into your skills directory:

```sh
# Claude Code, user-wide
cp -r supabase-audit ~/.claude/skills/
# or per project
cp -r supabase-audit .claude/skills/
```

The agent loads it when you ask to audit, harden or speed up a Supabase backend, or name it.

## Layout

```
supabase-audit/
  SKILL.md                    method, rules, the ten recurring findings
  references/security.md      grants, DEFINER guards, RLS, secrets, enumeration
  references/performance.md   plan caching, inlining, indexes, search, per-row work
  references/measuring.md     read-only production bench, same-content proof
  references/testing.md       table-driven pgTAP access tests
  references/edge-functions.md
  sql/audit-queries.sql       17 read-only detection queries
  sql/rls-plan-scan.sql       RLS tables that call the caller per row (EXPLAIN only)
  scripts/audit.sh            run the detection queries, save a report
  scripts/bench.sh            read-only median ms + md5 as a real role
  scripts/gate.sh             CI gate against a committed baseline
  templates/supabase-audit.yml  GitHub Actions: weekly audit, gate, pgTAP on pull requests
```

## Automate it

```sh
export DATABASE_URL=postgres://readonly:...@host:5432/postgres
bash supabase-audit/scripts/audit.sh                      # report of every detection query
bash supabase-audit/scripts/bench.sh authenticated <uuid> calls.txt   # before a migration
bash supabase-audit/scripts/bench.sh authenticated <uuid> calls.txt   # after: compare
bash supabase-audit/scripts/gate.sh                       # fails if risk counts grew
```

Copy `templates/supabase-audit.yml` to `.github/workflows/` for the weekly run. Every script
forces a read-only session; the benchmark rolls back.

## Principles

- Every change is a migration file applied by CI; nothing is changed by hand on a database.
- Same output before and after, proven, unless the change is a deliberate fix.
- Measured on production data, read-only, as the role the client uses.
- A security fix is kept even when it costs time; its cost is measured and written down.
- Tests for access rules are written first and seen failing.

## Requirements

- A Supabase project (Postgres 15+; numbers in the docs come from Postgres 17).
- `psql` for the scripts, `pg_stat_statements` for traffic ranking, pgTAP on a non-production
  project for tests.
- Read access to production for the benches (they roll back, but they do run there).

## Changelog

See `CHANGELOG.md`.

## License

MIT
