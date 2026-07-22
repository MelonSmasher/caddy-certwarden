#!/bin/sh
# Build the plugin into a Caddy image for ONE Caddy version and tag/push it.
#
# Driven entirely by environment (set by the generated child pipeline):
#   CADDY_VERSION   required, e.g. 2.11.4
#   IS_LATEST       "true" if this is the newest Caddy version (gets :latest)
#   PUSH            "true" to push; otherwise build-only (compile/smoke check)
#   PLATFORMS       e.g. linux/amd64 or linux/amd64,linux/arm64
#   PLUGIN_TAG      release git tag (e.g. v0.1.0), or empty for non-release builds
#   IMAGE_GHCR, IMAGE_DOCKERHUB   required image paths
#   IMAGE_HARBOR   optional private-registry path (e.g. Harbor); host derived from it
#   IMAGE_SUFFIX   optional image-name suffix appended to every registry path,
#                  used for variant images (e.g. "-cache" -> caddy-certwarden-cache).
#                  Registry LOGIN hosts are unaffected (host is the path prefix).
#   EXTRA_WITH     optional space-separated `--with <module>` args passed to the
#                  Dockerfile (variant plugins, e.g. Souin cache-handler + storages)
#   IMAGE_TITLE / IMAGE_DESCRIPTION  optional OCI label overrides for the variant
#   GHCR_USER/GHCR_TOKEN, DOCKERHUB_USER/DOCKERHUB_TOKEN, HARBOR_USER/HARBOR_TOKEN
#
# Tagging (per registry):
#   caddy<A.B.C>            moving: newest plugin build for that exact Caddy patch
#   caddy<A.B>             moving: newest plugin build for that Caddy minor line
#   <X.Y.Z>-caddy<A.B.C>   immutable: only on plugin release tags
#   latest                 only on the newest Caddy version
set -eu

: "${CADDY_VERSION:?CADDY_VERSION is required}"
: "${IMAGE_GHCR:?IMAGE_GHCR is required}"
: "${IMAGE_DOCKERHUB:?IMAGE_DOCKERHUB is required}"

PUSH="${PUSH:-false}"
IS_LATEST="${IS_LATEST:-false}"
IS_MAJOR_LATEST="${IS_MAJOR_LATEST:-false}"
PLUGIN_TAG="${PLUGIN_TAG:-}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
IMAGE_SUFFIX="${IMAGE_SUFFIX:-}"
EXTRA_WITH="${EXTRA_WITH:-}"
IMAGE_TITLE="${IMAGE_TITLE:-caddy-certwarden}"
IMAGE_DESCRIPTION="${IMAGE_DESCRIPTION:-Caddy with the certwarden certificate manager (cached certificates from Cert Warden)}"

CV="$CADDY_VERSION"
CV_MINOR="${CV%.*}"  # 2.11.4 -> 2.11
CV_MAJOR="${CV%%.*}" # 2.11.4 -> 2

# Variant image paths = base path + IMAGE_SUFFIX (e.g. .../caddy-certwarden-cache).
REGISTRIES="${IMAGE_GHCR}${IMAGE_SUFFIX} ${IMAGE_DOCKERHUB}${IMAGE_SUFFIX}"
if [ -n "${IMAGE_HARBOR:-}" ]; then
	REGISTRIES="$REGISTRIES ${IMAGE_HARBOR}${IMAGE_SUFFIX}"
fi

TAGS=""
for reg in $REGISTRIES; do
	TAGS="$TAGS --tag ${reg}:caddy${CV} --tag ${reg}:caddy${CV_MINOR}"
	# Major-line tag (e.g. caddy2) only on the newest build of that major, so it
	# isn't raced/overwritten by older minors in the matrix.
	if [ "$IS_MAJOR_LATEST" = "true" ]; then
		TAGS="$TAGS --tag ${reg}:caddy${CV_MAJOR}"
	fi
	if [ -n "$PLUGIN_TAG" ]; then
		TAGS="$TAGS --tag ${reg}:${PLUGIN_TAG#v}-caddy${CV}"
	fi
	if [ "$IS_LATEST" = "true" ]; then
		TAGS="$TAGS --tag ${reg}:latest"
	fi
done

OUTPUT=""
if [ "$PUSH" = "true" ]; then
	echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
	echo "$DOCKERHUB_TOKEN" | docker login docker.io -u "$DOCKERHUB_USER" --password-stdin
	if [ -n "${IMAGE_HARBOR:-}" ]; then
		echo "$HARBOR_TOKEN" | docker login "${IMAGE_HARBOR%%/*}" -u "$HARBOR_USER" --password-stdin
	fi
	OUTPUT="--push"
fi

echo "Building caddy=${CV} suffix='${IMAGE_SUFFIX}' latest=${IS_LATEST} push=${PUSH} platforms=${PLATFORMS}"
echo "Extra plugins:${EXTRA_WITH:+ ${EXTRA_WITH}}"
echo "Tags:${TAGS}"

run_build() {
	# Word-splitting of $TAGS and $OUTPUT is intentional; EXTRA_WITH is passed as
	# a single quoted build-arg (the Dockerfile word-splits it into --with flags).
	# shellcheck disable=SC2086
	docker buildx build \
		--platform "${PLATFORMS}" \
		--build-arg CADDY_VERSION="${CV}" \
		--build-arg EXTRA_WITH="${EXTRA_WITH}" \
		--build-arg IMAGE_TITLE="${IMAGE_TITLE}" \
		--build-arg IMAGE_DESCRIPTION="${IMAGE_DESCRIPTION}" \
		${TAGS} \
		${OUTPUT} \
		.
}

if [ "$PUSH" = "true" ]; then
	# Harbor occasionally returns 499 (client-closed) on individual blob
	# uploads, usually a backend/MinIO timeout. Blobs are content-addressable,
	# so already-uploaded layers skip on retry and this is cheap.
	attempt=1
	while true; do
		if run_build; then
			break
		fi
		if [ "$attempt" -ge 3 ]; then
			echo "ERROR: build/push failed after 3 attempts" >&2
			exit 1
		fi
		echo "Attempt ${attempt} failed; retrying in 15s..."
		attempt=$((attempt + 1))
		sleep 15
	done
else
	run_build
fi
