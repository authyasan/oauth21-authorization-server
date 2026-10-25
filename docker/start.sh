#!/bin/sh
set -eu

if [ ! -s keys/private.pem ] || [ ! -s keys/jwks.json ]; then
  echo '初期化が必要です: docker compose -f compose.quickstart.yaml run --rm --build setup' >&2
  exit 1
fi

exec npm start
