#!/bin/bash
# Runs after init.sql (alphabetically last via 'z' prefix).
# Initializes the midPoint native PostgreSQL repository schema.
set -e

# Skip if schema already present (idempotent — safe on volume reuse)
ALREADY=$(psql -U midpoint -d midpoint -tAc \
    "SELECT count(*) FROM information_schema.tables \
     WHERE table_schema='public' AND table_name='m_global_metadata'" \
    2>/dev/null || echo "0")
if [ "$ALREADY" = "1" ]; then
    echo "[midpoint-init] Schema already present — skipping."
    exit 0
fi

echo "[midpoint-init] Initializing midPoint native PostgreSQL schema..."
export PGPASSWORD=midpoint_pass
psql -U midpoint -d midpoint -f /midpoint-sql/postgres.sql
psql -U midpoint -d midpoint -f /midpoint-sql/postgres-quartz.sql
psql -U midpoint -d midpoint -f /midpoint-sql/postgres-audit.sql
echo "[midpoint-init] Schema initialized."
