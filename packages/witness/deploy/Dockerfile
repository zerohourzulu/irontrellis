# IronTrellis witness server image.
#
# Build from the repository root (the build needs the pnpm workspace: core + witness). BuildKit is
# required (the default builder since Docker 23 and in Docker Desktop): it reads
# Dockerfile.dockerignore beside this file and supports COPY --chmod.
#   docker build -f packages/witness/deploy/Dockerfile -t irontrellis-witness .
#
# Run (first start initializes the volume, printing the verifier key; see docker-entrypoint.sh):
#   docker run -d --name irontrellis-witness --hostname irontrellis-witness --restart unless-stopped \
#     -e IRONTRELLIS_WITNESS_NAME=witness.example.com \
#     -v irontrellis-witness:/data -p 127.0.0.1:8411:8411 irontrellis-witness
#   docker exec irontrellis-witness irontrellis-witness token create --data /data   # admin token, shown once
#   docker kill --signal HUP irontrellis-witness                                    # the server loads it
# A fixed --hostname lets a replacement container reclaim the lock left by a killed one.
# Never run two containers on one volume. Smoke test: packages/witness/deploy/smoke.sh <image>.
#
# Base image pinning. NODE_IMAGE defaults to the moving tag so a local build works anywhere; release
# builds should pin it by digest, which makes the base (and so the image) reproducible and makes a
# base update a reviewed change rather than a side effect of rebuilding:
#   docker buildx imagetools inspect node:22-alpine        # "Digest:" of the multi-arch index
#   docker build --build-arg NODE_IMAGE=node:22-alpine@sha256:<that digest> ...
# Use the index digest (not a per-platform manifest digest) so amd64 and arm64 both resolve. The CI
# workflow (.github/workflows/docker-witness.yml) passes its NODE_IMAGE env as this build arg: update
# the digest there when Node 22 or Alpine ship a fix, and let the smoke test pass before merging.
# The runtime needs Node >= 22.18.0 (the packages' engines field).
ARG NODE_IMAGE=node:22-alpine

# ---------------------------------------------------------------------------- build
# The build output is plain JavaScript (the witness and the core have no native addons), so it is
# built once on the builder's own platform and copied into every target platform's runtime stage:
# a linux/arm64 image built on amd64 runs only the runtime stage under emulation.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS build
ENV CI=true \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    NO_COLOR=1
WORKDIR /src
# pnpm at the exact version pinned by the root package.json "packageManager" field.
RUN corepack enable pnpm

# Dependencies first, from the lockfile alone, so this layer is cached until pnpm-lock.yaml changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
# Building behind a TLS-inspecting proxy: pass its CA as an optional build secret, used only for this
# download step and never stored in any layer:
#   docker build --secret id=build_ca,src=/path/to/proxy-ca.pem ...
# (first use of pnpm here also makes corepack download pnpm itself, so both honour it).
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi \
 && pnpm fetch

# Then the sources (the allowlist in Dockerfile.dockerignore: the root manifests and the core and
# witness packages without node_modules, dist or tests).
COPY . .
# --frozen-lockfile: fail rather than resolve anything the lockfile does not already pin; the filter
# checks and installs only the witness and its workspace dependency (the core).
# (The deploy below may read registry metadata, so this step gets the same optional CA.)
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_ca; fi \
 && pnpm install --frozen-lockfile --offline --filter "@ramex-labs/irontrellis-witness..." \
 && pnpm --filter "@ramex-labs/irontrellis-witness..." run build \
 && pnpm --filter @ramex-labs/irontrellis-witness deploy --prod --config.inject-workspace-packages=true /out \
 && node --input-type=module -e "await import('/out/node_modules/@ramex-labs/irontrellis/dist/index.js')" \
 && node /out/bin/irontrellis-witness.mjs --version
# `deploy --prod` writes a self-contained copy of the witness package (its "files": bin, dist, README,
# LICENSE, NOTICE) with a production node_modules holding only its workspace core, injected as a copy
# of its packed files (built dist, no sources, no dev dependencies) behind a link relative to /out, so
# the directory can move to the runtime stage. inject-workspace-packages is set for this command only:
# the workspace itself keeps linking its packages. (The legacy deploy would link the core back to
# /src, which does not exist in the runtime stage.) The import check fails the build if it ever does.

# ---------------------------------------------------------------------------- runtime
FROM ${NODE_IMAGE} AS runtime
ARG NODE_IMAGE
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="irontrellis-witness" \
      org.opencontainers.image.description="IronTrellis witness server: records owner-signed head statements in an append-only RFC 6962 Merkle log and returns signed receipts, so a history cannot be rolled back unnoticed." \
      org.opencontainers.image.source="https://github.com/zerohourzulu/irontrellis" \
      org.opencontainers.image.url="https://github.com/zerohourzulu/irontrellis/tree/main/packages/witness" \
      org.opencontainers.image.documentation="https://github.com/zerohourzulu/irontrellis/blob/main/docs/WITNESS.md" \
      org.opencontainers.image.vendor="RAmEx Labs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.base.name="${NODE_IMAGE}"

# No init process and no apk packages: the entrypoint execs node, so the server itself is PID 1 and
# installs its own SIGTERM/SIGINT (graceful stop: stop accepting, finish in-flight appends, release
# server.lock) and SIGHUP (reload admin tokens) handlers; it spawns no children, so there is nothing
# to reap. (Use `docker run --init` if you want an init anyway.) This also keeps the build free of
# any package-mirror download beyond the pinned base image and the npm registry.
# npm, npx, corepack and yarn are removed: the server needs only node, and they are the bulk of the
# base image's CVE surface. The service user owns nothing but /data.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && addgroup -S -g 10001 witness \
 && adduser -S -D -H -u 10001 -G witness -h /data -s /sbin/nologin witness \
 && mkdir -p /data \
 && chown witness:witness /data \
 && chmod 0700 /data

# Code is owned by root and read-only for the service user.
COPY --from=build /out /opt/irontrellis-witness
COPY --chmod=0755 packages/witness/deploy/docker-entrypoint.sh /usr/local/bin/irontrellis-witness-entrypoint
RUN chmod 0755 /opt/irontrellis-witness/bin/irontrellis-witness.mjs \
 && ln -s /opt/irontrellis-witness/bin/irontrellis-witness.mjs /usr/local/bin/irontrellis-witness

ENV NODE_ENV=production
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8411
# No curl in the image: busybox wget (via the entrypoint's `healthcheck`, which honours
# IRONTRELLIS_WITNESS_HEALTH_URL when --listen moves the port). /healthz answers 503 after a storage failure.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/irontrellis-witness-entrypoint", "healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/irontrellis-witness-entrypoint"]
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:8411"]
