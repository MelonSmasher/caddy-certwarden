#!/bin/sh
# Functional test: run the built plugin image against a REAL Cert Warden and
# verify Caddy serves exactly the certificate Cert Warden holds.
#
# It fetches the fixture certificate straight from Cert Warden (the "expected"
# cert), starts Caddy with the plugin pointed at the same Cert Warden, and
# asserts the served leaf fingerprint matches.
#
# Required env:
#   IMAGE         the caddy-certwarden image to test
#   CW_TEST_URL   Cert Warden base URL (e.g. https://certwarden.example.com)
#   CW_TEST_CERT  the certificate NAME in Cert Warden (not its subject)
#   CW_TEST_KEY   combined download key: <cert-api-key>.<private-key-api-key>
# Optional:
#   PROBE_HOST      host:port target maps to the published container port.
#                   Default "docker" (the GitLab dind service). Use 127.0.0.1
#                   against a local Docker daemon.
#   CADDY_RUN_ARGS  extra `docker create` args, e.g. an --add-host mapping when
#                   the container's resolver can't see an internal Cert Warden.
#
# Needs curl + openssl on the runner, plus a Docker daemon.
set -eu

: "${IMAGE:?IMAGE is required}"
: "${CW_TEST_URL:?CW_TEST_URL is required}"
: "${CW_TEST_CERT:?CW_TEST_CERT is required}"
: "${CW_TEST_KEY:?CW_TEST_KEY is required}"
PROBE_HOST="${PROBE_HOST:-docker}"

work="$(mktemp -d)"
container="cwfunc-caddy-$$"
cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

echo ">> fetching the fixture certificate directly from Cert Warden"
curl -fsS -H "X-API-Key: ${CW_TEST_KEY}" \
	"${CW_TEST_URL%/}/certwarden/api/v1/download/privatecertchains/${CW_TEST_CERT}" \
	-o "$work/expected.pem"
sni="$(openssl x509 -in "$work/expected.pem" -noout -ext subjectAltName 2>/dev/null \
	| grep -oE 'DNS:[^,]+' | head -1 | cut -d: -f2 | tr -d ' ')"
[ -n "$sni" ] || { echo "could not read a DNS SAN from the fixture cert"; exit 1; }
expected="$(openssl x509 -in "$work/expected.pem" -noout -fingerprint -sha256)"
echo "   cert=${CW_TEST_CERT} sni=${sni}"

echo ">> writing the test Caddyfile"
cat > "$work/Caddyfile" <<EOF
{
	auto_https disable_certs
	admin off
	http_port 8080
	https_port 8443
}
https://${sni}:8443 {
	tls {
		get_certificate certwarden {
			base_url ${CW_TEST_URL}
			certificate ${CW_TEST_CERT} {env.CW_TEST_KEY}
		}
	}
	respond "ok"
}
EOF

echo ">> starting the plugin container"
# create + cp + start rather than a bind mount: under docker-in-docker a bind
# mount would come from the dind host, not this job's filesystem.
# shellcheck disable=SC2086
docker create --name "$container" -p 8443:8443 \
	-e CW_TEST_KEY="$CW_TEST_KEY" ${CADDY_RUN_ARGS:-} "$IMAGE" >/dev/null
docker cp "$work/Caddyfile" "$container:/etc/caddy/Caddyfile"
docker start "$container" >/dev/null

echo ">> probing ${PROBE_HOST}:8443 (SNI ${sni})"
served=""
i=0
while [ "$i" -lt 20 ]; do
	served="$(echo | openssl s_client -connect "${PROBE_HOST}:8443" -servername "$sni" 2>/dev/null \
		| openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
	[ -n "$served" ] && break
	i=$((i + 1))
	sleep 2
done

echo "served:   ${served:-<none>}"
echo "expected: ${expected}"
if [ -n "$served" ] && [ "$served" = "$expected" ]; then
	echo "PASS: the plugin served the Cert Warden certificate"
else
	echo "FAIL: served certificate does not match the one from Cert Warden"
	echo "--- container logs ---"
	docker logs "$container" 2>&1 | tail -20
	exit 1
fi
