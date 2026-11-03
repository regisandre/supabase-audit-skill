#!/usr/bin/env bash
# CI gate: fail when the number of risky objects grows past a committed baseline.
#   DATABASE_URL=... ./scripts/gate.sh [baseline-file]
# Counts (read-only): SECURITY DEFINER functions that anon can execute, policies open to
# everyone, public tables with RLS off. The baseline file holds "definer_anon open_policies no_rls".
# Start with the current numbers, then only ever lower them.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
base="${1:-.supabase-audit-baseline}"
export PGOPTIONS='-c default_transaction_read_only=on'
q() { psql "$DATABASE_URL" -X -q -t -A -c "$1"; }
now="$(q "select
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.prosecdef and has_function_privilege('anon',p.oid,'EXECUTE')),
  (select count(*) from pg_policies where schemaname='public' and (qual='true' or with_check='true')),
  (select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind in ('r','p') and not c.relrowsecurity)" | tr '|' ' ')"
echo "now:      $now"
if [ ! -f "$base" ]; then echo "no baseline at $base; write one with: echo '$now' > $base"; exit 0; fi
echo "baseline: $(cat "$base")"
read -r a b c <<<"$now"; read -r x y z <<<"$(cat "$base")"
if [ "$a" -gt "$x" ] || [ "$b" -gt "$y" ] || [ "$c" -gt "$z" ]; then
  echo "FAIL: a count grew past the baseline" >&2; exit 1
fi
echo "ok"
