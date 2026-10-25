#!/bin/sh
set -eu
umask 077

# 再実行で既存の署名鍵を上書きしない。片方だけある場合も自動修復しない。
if [ -s keys/private.pem ] && [ -s keys/jwks.json ]; then
  echo '既存の署名鍵を使用します。'
elif [ -e keys/private.pem ] || [ -e keys/jwks.json ]; then
  echo '署名鍵が片方しかないか、空のファイルがあります。鍵ファイルを確認してください。自動上書きせず停止します。' >&2
  exit 1
else
  npm run generate-keys
fi

# 初回の空DBに適用する。通常起動からは呼ばず、破壊的変更を強制しない。
npm run db:push
npm run db:seed
