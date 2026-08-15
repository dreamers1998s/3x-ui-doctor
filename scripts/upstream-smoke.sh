#!/usr/bin/env bash
set -euo pipefail

: "${XUI_IMAGE_350:?XUI_IMAGE_350 is required}"
: "${XUI_IMAGE_360:?XUI_IMAGE_360 is required}"

name="xui-doctor-upstream"
volume="xui-doctor-upstream-${GITHUB_RUN_ID:-local}-$$"
work="$(mktemp -d)"
port=12053
base="https://localhost:${port}/doctor-ci"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/key.pem" -out "$work/cert.pem" -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
pin="$(openssl x509 -in "$work/cert.pem" -outform der | sha256sum | awk '{print $1}')"
docker volume create "$volume" >/dev/null

wait_http() {
  local scheme="$1"
  for _ in $(seq 1 60); do
    if curl --silent --fail "${scheme}://localhost:${port}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$name"
  return 1
}

wait_https() {
  for _ in $(seq 1 60); do
    if curl --silent --fail --cacert "$work/cert.pem" "$base/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$name"
  return 1
}

start_initial() {
  docker run -d --name "$name" \
    -p "127.0.0.1:${port}:2053" \
    -v "$volume:/etc/x-ui" -v "$work:/cert:ro" \
    -e XUI_ENABLE_FAIL2BAN=false "$XUI_IMAGE_350" >/dev/null
  wait_http http
  docker exec "$name" /app/x-ui setting \
    -username doctor-ci -password doctor-ci-password \
    -port 2053 -webBasePath /doctor-ci/ \
    -webCert /cert/cert.pem -webCertKey /cert/key.pem >/dev/null
  docker restart "$name" >/dev/null
  wait_https
}

mint_token() {
  curl --silent --show-error --fail --cacert "$work/cert.pem" \
    -c "$work/cookies" "$base/csrf-token" > "$work/csrf-before-login.json"
  local csrf
  csrf="$(jq -er '.obj | select(type == "string" and length > 0)' "$work/csrf-before-login.json")"

  curl --silent --show-error --fail --cacert "$work/cert.pem" \
    -b "$work/cookies" -c "$work/cookies" \
    -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{"username":"doctor-ci","password":"doctor-ci-password"}' \
    "$base/login" > "$work/login.json"
  jq -e '.success == true' "$work/login.json" >/dev/null

  curl --silent --show-error --fail --cacert "$work/cert.pem" \
    -b "$work/cookies" -c "$work/cookies" \
    "$base/csrf-token" > "$work/csrf-after-login.json"
  csrf="$(jq -er '.obj | select(type == "string" and length > 0)' "$work/csrf-after-login.json")"

  curl --silent --show-error --fail --cacert "$work/cert.pem" \
    -b "$work/cookies" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data '{"name":"doctor-ci"}' \
    "$base/panel/api/setting/apiTokens/create" > "$work/token.json"
  XUI_CI_TOKEN="$(jq -r '.obj.token' "$work/token.json")"
  test -n "$XUI_CI_TOKEN" && test "$XUI_CI_TOKEN" != null
  export XUI_CI_TOKEN
}

write_config() {
  cat > "$work/doctor.yaml" <<EOF
schema_version: 1
panels:
  - id: master
    role: master
    url: $base
    token_env: XUI_CI_TOKEN
    expected_guid: 11111111-1111-4111-8111-111111111111
    tls_pin_sha256: $pin
redaction:
  key_env: XUI_DOCTOR_HMAC_KEY
  key_id: upstream-ci-v1
subscription:
  sample_cap: 10
traffic:
  relative_threshold: 0.05
  absolute_threshold_bytes: 67108864
  limit_grace: 0s
transport:
  request_timeout: 10s
  panel_concurrency: 1
  requests_per_panel: 1
report:
  include_network_identifiers: false
EOF
}

accept_audit_exit() {
  local code="$1"
  if [[ "$code" != 0 && "$code" != 2 ]]; then
    echo "unexpected Doctor exit code: $code" >&2
    return 1
  fi
}

start_initial
mint_token
write_config
export XUI_DOCTOR_HMAC_KEY='upstream-smoke-stable-hmac-key-32-bytes-minimum'

set +e
./dist/xui-doctor preflight --config "$work/doctor.yaml" --target v3.6.0 \
  --baseline-out "$work/before.json" --observe 0s --format json --output "$work/preflight.json"
preflight_code=$?
set -e
accept_audit_exit "$preflight_code"
jq -e '.schema_version == 1 and (.readiness == "READY" or .readiness == "INCONCLUSIVE")' "$work/preflight.json" >/dev/null

docker rm -f "$name" >/dev/null
docker run -d --name "$name" \
  -p "127.0.0.1:${port}:2053" \
  -v "$volume:/etc/x-ui" -v "$work:/cert:ro" \
  -e XUI_ENABLE_FAIL2BAN=false "$XUI_IMAGE_360" >/dev/null
wait_https

set +e
./dist/xui-doctor verify --config "$work/doctor.yaml" --baseline "$work/before.json" \
  --observe 0s --format json --output "$work/verify.json"
verify_code=$?
set -e
accept_audit_exit "$verify_code"
jq -e '.schema_version == 1 and (.readiness == "READY" or .readiness == "INCONCLUSIVE")' "$work/verify.json" >/dev/null
