# Build a Caddy image with the certwarden TLS certificate manager compiled in.
#
# Cross-compiles for multi-arch WITHOUT QEMU emulation: the builder stage is
# pinned to the native BUILDPLATFORM and cross-compiles the (pure-Go, CGO-free)
# binary to TARGETARCH via GOARCH, which xcaddy/go honor. Only the tiny runtime
# stage is per-target-arch, and it just copies the binary (no target-arch code
# runs during the build), so no binfmt/QEMU is needed.
#
# CADDY_VERSION pins the Caddy release; the CI passes it per matrix job.
ARG CADDY_VERSION=2.11.4

FROM --platform=$BUILDPLATFORM caddy:${CADDY_VERSION}-builder AS build
ARG TARGETOS
ARG TARGETARCH
# EXTRA_WITH: additional space-separated `--with <module>` args for xcaddy, used
# to build variant images. It is intentionally word-split by the shell below, so
# it can carry several `--with` flags (e.g. the -cache variant: Souin
# cache-handler + storage backends). Empty for the plain image.
ARG EXTRA_WITH=""
# The caddy builder image pins GOTOOLCHAIN=local. Allow Go to fetch a newer
# toolchain when a plugin's go.mod requires one beyond the builder's Go (the
# -cache variant's darkweak storages track the newest Go). No-op when the
# builder already satisfies the requirement.
ENV GOTOOLCHAIN=auto
COPY . /src
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    xcaddy build \
      --with github.com/MelonSmasher/caddy-certwarden=/src \
      ${EXTRA_WITH} \
      --output /out/caddy

FROM caddy:${CADDY_VERSION}
# Title/description are build-args so each variant labels itself accurately.
ARG IMAGE_TITLE="caddy-certwarden"
ARG IMAGE_DESCRIPTION="Caddy with the certwarden certificate manager (cached certificates from Cert Warden)"
LABEL org.opencontainers.image.title="${IMAGE_TITLE}"
LABEL org.opencontainers.image.description="${IMAGE_DESCRIPTION}"
LABEL org.opencontainers.image.source="https://github.com/MelonSmasher/caddy-certwarden"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/caddy /usr/bin/caddy
