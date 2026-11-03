#!/usr/bin/env bash
# Run the read-only detection queries against a database and save one report.
#   DATABASE_URL=postgres://... ./scripts/audit.sh [report-file]
# The session is forced read-only, so nothing can be written even by mistake.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a connection string (a read-only role is enough)}"
here="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-audit-report-$(date +%Y%m%d%H%M%S).txt}"
export PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=60000'
{
  echo "# supabase-audit report $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  psql "$DATABASE_URL" -X -q -P pager=off -v ON_ERROR_STOP=0 -f "$here/sql/audit-queries.sql"
} | tee "$out"
echo "report: $out" >&2
