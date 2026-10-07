#!/usr/bin/env bash
# Dev certificate authority and Postgres server certificate for the lab. Keys are written next to this
# script and are gitignored; only this script and the public CA certificate are meant to be shared.
set -euo pipefail
export MSYS_NO_PATHCONV=1  # Git Bash would rewrite the -subj argument into a Windows path
cd "$(dirname "$0")"

if [ ! -f ca.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 825 \
    -subj "/CN=Sentinel Dev CA"
fi
if [ ! -f server.key ]; then
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
  printf "subjectAltName=DNS:localhost,DNS:postgres,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 825 -extfile server.ext
  rm -f server.csr server.ext ca.srl
fi
if [ ! -f redis.key ]; then
  openssl req -newkey rsa:2048 -nodes -keyout redis.key -out redis.csr -subj "/CN=redis"
  printf "subjectAltName=DNS:redis,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
" > redis.ext
  openssl x509 -req -in redis.csr -CA ca.crt -CAkey ca.key -CAcreateserial     -out redis.crt -days 825 -extfile redis.ext
  rm -f redis.csr redis.ext ca.srl
fi
chmod 600 ./*.key
echo "dev CA: $(pwd)/ca.crt (Postgres and Redis server certificates issued)"
