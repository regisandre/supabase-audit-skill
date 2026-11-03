#!/usr/bin/env bash
# Read-only benchmark of SQL calls as a real role, rolled back. Prints median ms and an md5 per call.
#   DATABASE_URL=... ./scripts/bench.sh <role> <jwt-sub-uuid|-> <calls-file> [runs]
# calls-file: one SQL statement per line that returns one text value, for example
#   SELECT public.fn_a(42)::text
#   SELECT coalesce(json_agg(r)::text, '') FROM public.fn_b(42) r
# Use '-' as the uuid for anon. Run the same command before and after a migration and compare.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
role="${1:?role: anon | authenticated | service_role}"
sub="${2:?jwt sub uuid, or - for none}"
file="${3:?file with one statement per line}"
runs="${4:-15}"
case "$role" in anon|authenticated|service_role) ;; *) echo "unknown role" >&2; exit 2;; esac
claims="{\"role\":\"$role\"}"
[ "$sub" != "-" ] && claims="{\"role\":\"$role\",\"sub\":\"$sub\"}"
calls="$(sed -e "s/'/''/g" -e "s/^/'/" -e "s/\$/'/" "$file" | paste -sd, -)"
sql=$(cat <<SQL
DO \$bench\$
DECLARE
  calls text[] := ARRAY[$calls];
  q text; i int; t0 timestamptz; ms numeric[]; out text; report text := '';
BEGIN
  PERFORM set_config('request.jwt.claims', '$claims', true);
  EXECUTE 'SET LOCAL ROLE $role';
  FOREACH q IN ARRAY calls LOOP
    EXECUTE q INTO out;
    ms := '{}';
    FOR i IN 1..$runs LOOP
      t0 := clock_timestamp();
      EXECUTE q INTO out;
      ms := ms || (extract(epoch FROM clock_timestamp() - t0) * 1000)::numeric;
    END LOOP;
    report := report || format(E'%s | median %s ms | md5 %s\n', left(q, 90),
      round((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) FROM unnest(ms) x)::numeric, 3),
      left(md5(coalesce(out, '')), 8));
  END LOOP;
  RAISE EXCEPTION E'BENCH\n%', report;
END \$bench\$;
SQL
)
# The report travels in the error message of the rolled-back block.
psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=0 -c "$sql" 2>&1 | sed -e '/^ERROR:  BENCH/d' -e '/^CONTEXT:/,$d'
