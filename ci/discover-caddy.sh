#!/bin/sh
# Discover which Caddy versions to build against and generate a child pipeline
# (one build job per version). Policy: the latest patch of the last N minor
# release lines, where N = CADDY_MINORS (default 3).
#
# A version is a candidate only if a `caddy:<version>-builder` image exists,
# which is implied by the plain `<version>` tag on Docker Hub's official image.
#
# Push vs. smoke:
#   - Scheduled pipelines and plugin release tags (vX.Y.Z) build multi-arch and
#     push all registries.
#   - Everything else (branches/MRs) builds amd64 only and does not push, acting
#     as a compile/compatibility gate across every supported Caddy version.
#
# Four image VARIANTS are built for every selected Caddy version, differing only
# in the plugins compiled in (registry path = base path + suffix; see
# build-and-push.sh IMAGE_SUFFIX):
#   - base       (caddy-certwarden)             the plugin only.
#   - cfip       (caddy-certwarden-cfip)        + WeidiDeng/caddy-cloudflare-ip,
#                the Cloudflare trusted-proxy IP range source.
#   - cache      (caddy-certwarden-cache)       + the Souin cache-handler and
#                storage backends, for proxies that also do response caching.
#   - cache-cfip (caddy-certwarden-cache-cfip)  + both of the above.
# The cache and cache-cfip variants carry the darkweak storages, which pin a
# newer Caddy, so they are only built for Caddy >= CACHE_CADDY_MIN (below); the
# base and cfip variants cover the full base range (Caddy >= CADDY_MIN).
# None of the variants add the Cloudflare *DNS* plugin: with Cert Warden the
# proxy no longer performs ACME/DNS-01, so that token is not needed.
#
# Requires: curl, jq. Reads (from the parent pipeline): CADDY_MINORS,
# IMAGE_GHCR, IMAGE_DOCKERHUB, IMAGE_HARBOR, CI_COMMIT_TAG, CI_PIPELINE_SOURCE.
set -eu

MINORS="${CADDY_MINORS:-3}"

# The -cache variant carries the darkweak souin cache-handler + storage backends,
# which track the newest Caddy: the storages monorepo currently pins Caddy
# v2.11.2 (and Go 1.26.1). So the cache variant has a HIGHER Caddy floor than the
# base plugin and is only built for Caddy >= CACHE_CADDY_MIN. Bump this when the
# storages raise their minimum (check `darkweak/storages/*/caddy` go.mod).
CACHE_CADDY_MIN="${CACHE_CADDY_MIN:-2.11.2}"

# Extra xcaddy modules for the -cache variant: Souin cache-handler + the storage
# backends (mirrors the caddy-cloudflare-cache image, minus the Cloudflare DNS
# plugin). Kept on one logical line; the shell removes the backslash-newlines.
CACHE_WITH="--with github.com/darkweak/souin/plugins/caddy \
--with github.com/darkweak/storages/badger/caddy \
--with github.com/darkweak/storages/redis/caddy \
--with github.com/darkweak/storages/etcd/caddy \
--with github.com/darkweak/storages/nuts/caddy \
--with github.com/darkweak/storages/olric/caddy \
--with github.com/darkweak/storages/nats/caddy \
--with github.com/darkweak/storages/otter/caddy \
--with github.com/darkweak/storages/simplefs/caddy"

# Extra xcaddy module for the -cfip variant: the Cloudflare trusted-proxy IP
# range source (used by the `trusted_proxies cloudflare` directive). It's a small
# pure-Go plugin with a low Caddy floor (go.mod requires only v2.6.3), so it
# builds across the full base range and needs no separate floor knob.
CFIP_WITH="--with github.com/WeidiDeng/caddy-cloudflare-ip"

# Collect plain X.Y.Z release tags from the official Caddy image.
tmp="$(mktemp)"
page=1
while [ "$page" -le 5 ]; do
	resp="$(curl -fsSL "https://hub.docker.com/v2/repositories/library/caddy/tags/?page_size=100&page=${page}")" || break
	printf '%s\n' "$resp" | jq -r '.results[].name' \
		| grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' >>"$tmp" || true
	# Stop when Docker Hub reports no further pages.
	printf '%s\n' "$resp" | jq -e '.next != null' >/dev/null 2>&1 || break
	page=$((page + 1))
done

# Minimum supported Caddy version = the caddyserver/caddy/v2 requirement in
# go.mod. Older release lines pull transitively incompatible deps (certmagic /
# libdns API skew) and can't be built, so they're filtered out here rather than
# failing the pipeline. Reading it from go.mod keeps the two in sync with no
# separate knob.
CADDY_MIN="$(grep -E 'caddyserver/caddy/v2 v[0-9]' go.mod | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
CADDY_MIN="${CADDY_MIN:-0.0.0}"

# Drop candidates below the floor (version-aware compare: keep cv iff cv >= min).
if [ -s "$tmp" ]; then
	kept="$(mktemp)"
	while IFS= read -r cv; do
		[ -n "$cv" ] || continue
		if [ "$(printf '%s\n%s\n' "$cv" "$CADDY_MIN" | sort -V | head -n 1)" = "$CADDY_MIN" ]; then
			printf '%s\n' "$cv" >>"$kept"
		fi
	done <"$tmp"
	mv "$kept" "$tmp"
fi

# Sorted descending + unique, then keep the first (highest) patch per minor,
# then take the newest N minors.
SELECTED="$(sort -Vr -u "$tmp" | awk -F. '!seen[$1"."$2]++' | head -n "$MINORS")"
rm -f "$tmp"

if [ -z "$SELECTED" ]; then
	echo "ERROR: no Caddy versions discovered" >&2
	exit 1
fi
NEWEST="$(printf '%s\n' "$SELECTED" | head -n 1)"

PUSH=false
if [ "${CI_PIPELINE_SOURCE:-}" = "schedule" ]; then
	PUSH=true
fi
if printf '%s' "${CI_COMMIT_TAG:-}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
	PUSH=true
fi

PLATFORMS="linux/amd64"
if [ "$PUSH" = "true" ]; then
	PLATFORMS="linux/amd64,linux/arm64"
fi

# On non-push (branch/MR) pipelines, only smoke-build the newest Caddy version.
# This keeps routine branch commits light on the shared VM (docker) runner; the
# full multi-version matrix runs on schedules and release tags.
if [ "$PUSH" != "true" ]; then
	SELECTED="$NEWEST"
fi

echo "policy:   latest patch of the last ${MINORS} minor line(s), Caddy >= ${CADDY_MIN} (cache variant >= ${CACHE_CADDY_MIN})"
echo "selected: $(printf '%s ' $SELECTED)"
echo "newest:   ${NEWEST}"
echo "push:     ${PUSH}   platforms: ${PLATFORMS}"

# Emit one build job. Args:
#   $1 job-name + IMAGE_SUFFIX (e.g. "" or "-cache")
#   $2 EXTRA_WITH   $3 IMAGE_TITLE   $4 IMAGE_DESCRIPTION
# Reads loop-locals: v, latest, major_latest.
emit_build_job() {
	cat <<EOF
build-caddy-${v}${1}:
  stage: build
  # Route to the dedicated docker-on-VM runner; the k8s runner is too light
  # for image builds (matches the Account Activator / Moodle / Canvas pattern).
  tags:
    - docker
  image: docker:latest
  services:
    - docker:dind
  variables:
    CADDY_VERSION: "${v}"
    IS_LATEST: "${latest}"
    IS_MAJOR_LATEST: "${major_latest}"
    PUSH: "${PUSH}"
    PLATFORMS: "${PLATFORMS}"
    PLUGIN_TAG: "${CI_COMMIT_TAG:-}"
    IMAGE_GHCR: "${IMAGE_GHCR}"
    IMAGE_DOCKERHUB: "${IMAGE_DOCKERHUB}"
    IMAGE_HARBOR: "${IMAGE_HARBOR:-}"
    IMAGE_SUFFIX: "${1}"
    EXTRA_WITH: "${2}"
    IMAGE_TITLE: "${3}"
    IMAGE_DESCRIPTION: "${4}"
  before_script:
    # docker-container driver enables multi-platform output. No binfmt/QEMU
    # needed: the Dockerfile cross-compiles from the native build platform.
    - docker buildx create --use --name builder
  script:
    - sh ci/build-and-push.sh
EOF
}

# Generate the child pipeline: one job per (selected Caddy version x variant).
# SELECTED is sorted newest-first, so the first version seen for each major line
# is that major's newest build and gets the moving caddy<major> tag (e.g. caddy2).
seen_majors=""
{
	echo "stages:"
	echo "  - build"
	for v in $SELECTED; do
		latest=false
		[ "$v" = "$NEWEST" ] && latest=true
		major="${v%%.*}"
		major_latest=false
		case " $seen_majors " in
			*" $major "*) ;;
			*) major_latest=true; seen_majors="$seen_majors $major" ;;
		esac
		# base + cfip: both cover the full base range (Caddy >= CADDY_MIN).
		emit_build_job "" "" \
			"caddy-certwarden" \
			"Caddy with the certwarden certificate manager (cached certificates from Cert Warden)"
		emit_build_job "-cfip" "$CFIP_WITH" \
			"caddy-certwarden-cfip" \
			"Caddy with the certwarden certificate manager plus the Cloudflare trusted-proxy IP range source"
		# cache + cache-cfip: the Souin storage plugins pin a newer Caddy than the
		# base plugin, so only emit them for Caddy >= CACHE_CADDY_MIN.
		if [ "$(printf '%s\n%s\n' "$v" "$CACHE_CADDY_MIN" | sort -V | head -n 1)" = "$CACHE_CADDY_MIN" ]; then
			emit_build_job "-cache" "$CACHE_WITH" \
				"caddy-certwarden-cache" \
				"Caddy with the certwarden certificate manager plus the Souin cache-handler and storage backends"
			emit_build_job "-cache-cfip" "$CACHE_WITH $CFIP_WITH" \
				"caddy-certwarden-cache-cfip" \
				"Caddy with the certwarden certificate manager, the Souin cache-handler and storage backends, and the Cloudflare trusted-proxy IP range source"
		else
			echo "  (skip cache + cache-cfip variants for ${v}: < ${CACHE_CADDY_MIN})" >&2
		fi
	done
} >child-pipeline.yml

echo "--- generated child-pipeline.yml ---"
cat child-pipeline.yml
