#!/usr/bin/env bash

set -euo pipefail

if [[ ! -d backend ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

clean_known_schema_dups() {
    local f="backend/ent/migrate/schema.go"
    [[ -f "$f" ]] || return 0

    for sym in IdempotencyRecordsColumns IdempotencyRecordsTable; do
        local cnt
        cnt="$(grep -n "^[[:space:]]*${sym}[[:space:]]*=" "$f" | wc -l | tr -d ' ')"
        if [[ "$cnt" -le 1 ]]; then
            continue
        fi

        echo "[fix] remove duplicate declaration: ${sym}"
        awk -v sym="$sym" '
          function brace_delta(s, i, c, d) {
            d=0
            for (i=1;i<=length(s);i++) {
              c=substr(s,i,1)
              if (c=="{") d++
              else if (c=="}") d--
            }
            return d
          }
          {
            if (!skip && $0 ~ "^[[:space:]]*" sym "[[:space:]]*=") {
              if (seen) {
                skip=1
                depth=brace_delta($0)
                next
              }
              seen=1
            }
            if (skip) {
              depth += brace_delta($0)
              if (depth <= 0) {
                skip=0
              }
              next
            }
            print
          }
        ' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
    done
}

run_ent_generate() {
    (cd backend && go generate ./ent)
}

echo "Run go generate ./ent ..."
if ! run_ent_generate; then
    echo "WARN: ent generate failed once, try schema duplicate cleanup and retry."
    clean_known_schema_dups
    run_ent_generate
fi

clean_known_schema_dups

echo "Run go generate ./cmd/server ..."
set +e
ERR_OUT="$(cd backend && go generate ./cmd/server 2>&1)"
GEN_EXIT=$?
set -e
if [[ $GEN_EXIT -ne 0 ]]; then
    echo "$ERR_OUT"
    echo "ERROR: wire generation failed."
    if grep -q "no provider found" <<<"$ERR_OUT"; then
        MISSING="$(grep "no provider found for" <<<"$ERR_OUT" | head -n 1 | sed -E 's/.*no provider found for ([^,]+),.*/\1/' || true)"
        if [[ -n "$MISSING" ]]; then
            echo "Hint: add provider/bind for missing type: ${MISSING}"
        fi
    fi
    exit 1
fi

if [[ "${LDAP_SYNC_TIDY:-0}" == "1" ]]; then
    echo "Run go mod tidy ..."
    (cd backend && go mod tidy)
fi

echo "OK: generated repair completed."
