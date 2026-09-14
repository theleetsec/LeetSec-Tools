# Dockerfile — LeetEnum container image (LeetSecurity LLC).
#
# Two targets:
#   runtime   the pipeline plus every DNS/HTTP tool          (~350 MB)
#   full      adds Chromium so phase 9 can take screenshots (~800 MB)
#
# Build:
#   docker build --target runtime -t leetenum:slim .
#   docker build --target full    -t leetenum:latest .
#
# Multi-arch, no per-architecture branching: every tool is Go source and
# massdns is built in-image, so amd64 and arm64 come off the same recipe.
#   docker buildx build --platform linux/amd64,linux/arm64 --target full \
#          -t ghcr.io/theleetsec/leetenum:latest --push .
#
# Run (results land in the mounted directory, owned by the invoking user):
#   docker run --rm -it -v "$PWD:/work" ghcr.io/theleetsec/leetenum example.com

# ---------------------------------------------------------------------------
# Stage 1 — build every Go tool and massdns.
#
# The tool list is read from lib/deps.sh rather than repeated here. Two copies
# of pinned versions is two copies that drift, and the shell installer
# and the image must agree on exactly what they installed.
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG MASSDNS_REF=6bfa47197d78e68b79041d494e280174cb2d6ae1

# libpcap is naabu's only cgo dependency; the rest is pure Go.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git ca-certificates make gcc libc6-dev libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out/bin \
    CGO_ENABLED=1 \
    GOFLAGS=-trimpath

COPY lib/deps.sh /build/deps.sh

RUN mkdir -p /out/bin \
 && . /build/deps.sh \
 && for entry in "${DEPS_GO_TOOLS[@]}"; do \
        IFS='|' read -r name module version _role <<<"$entry"; \
        echo "==> ${name} ${version}"; \
        go install "${module}@${version}"; \
    done \
 && ls -1 /out/bin

# massdns has no Go port and no Debian package, so it is compiled here. puredns
# is useless without it, and puredns is a required tool.
RUN git init -q /build/massdns \
 && git -C /build/massdns remote add origin https://github.com/blechschmidt/massdns.git \
 && git -C /build/massdns fetch -q --depth 1 origin "$MASSDNS_REF" \
 && git -C /build/massdns checkout -q --detach FETCH_HEAD \
 && make -C /build/massdns \
 && install -m 0755 /build/massdns/bin/massdns /out/bin/massdns

# ---------------------------------------------------------------------------
# Stage 2 — runtime.
#
# Debian slim rather than Alpine on purpose: naabu links against libpcap and the
# musl build is a source of subtle scan failures that only show up under load.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="LeetEnum" \
      org.opencontainers.image.description="Reconnaissance pipeline" \
      org.opencontainers.image.vendor="LeetSecurity LLC" \
      org.opencontainers.image.source="https://github.com/theleetsec/LeetSec-Tools" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bash ca-certificates curl jq tar gzip libpcap0.8 locales tzdata git dnsutils \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/ /usr/local/bin/

# ---------------------------------------------------------------------------
# A non-root user, for two independent reasons: results written into a bind
# mount should not come out owned by root, and naabu picks a connect scan
# automatically when it lacks raw-socket privileges, which is the correct
# default for a container that may be run anywhere.
#
# Grant CAP_NET_RAW at run time if a SYN scan is wanted:
#   docker run --cap-add=NET_RAW --user 0 ...
# ---------------------------------------------------------------------------
RUN useradd --create-home --shell /bin/bash --uid 1000 leet \
 && mkdir -p /work \
 && chown leet:leet /work

COPY leetenum.sh /opt/leetenum/leetenum.sh
COPY lib/        /opt/leetenum/lib/
RUN chmod +x /opt/leetenum/leetenum.sh \
 && ln -s /opt/leetenum/leetenum.sh /usr/local/bin/leetenum \
 && bash -n /opt/leetenum/leetenum.sh

# Nuclei templates are installed by `leetenum update` when needed.
USER leet
ENV HOME=/home/leet \
    LEETENUM_OUTPUT_DIR=/work \
    XDG_CONFIG_HOME=/home/leet/.config \
    XDG_CACHE_HOME=/home/leet/.cache

WORKDIR /work
VOLUME ["/work"]

# ENTRYPOINT, not CMD, so `docker run image example.com` reads naturally and the
# bare-domain form of the CLI works unchanged inside the container.
ENTRYPOINT ["leetenum"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Stage 3 — full, adds a browser for phase 9.
#
# Split out because Chromium roughly doubles the image, and most runs either
# skip screenshots or do not need them. `--skip p9` on the slim image is the
# equivalent, and the pipeline degrades to that on its own when no browser is
# found.
# ---------------------------------------------------------------------------
FROM runtime AS full
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        chromium fonts-liberation \
 && rm -rf /var/lib/apt/lists/*
ENV CHROME_PATH=/usr/bin/chromium
USER leet
ENTRYPOINT ["leetenum"]
CMD ["--help"]
