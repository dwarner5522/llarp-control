# LLARP for Umbrel: llarpd plus the control service (umbrel_node.py) and its proxy bridge.
# Build from the repo root:  docker build -f umbrel/Dockerfile .
FROM debian:trixie-slim AS build

ARG LLARP_REPO=https://github.com/majestrate/llarp.git
ARG LLARP_COMMIT=9540db2e76d2ff358c10c3e1da4a419d90122d92

RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      build-essential cmake ninja-build git pkg-config ca-certificates file \
      libuv1-dev libsodium-dev libjemalloc-dev libssl-dev libgeoip-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone -q "$LLARP_REPO" llarp \
 && git -C llarp checkout -q "$LLARP_COMMIT" \
 && git -C llarp submodule update -q --init --recursive

# NATIVE_BUILD=OFF: the image must run on any CPU of its architecture, not just the builder's
RUN cmake -S llarp -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DNATIVE_BUILD=OFF \
      -DWITH_SETCAP=OFF \
      -DWITH_SYSTEMD=OFF \
      -DWITH_TESTS=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DLLARP_VERSIONTAG="$(echo "$LLARP_COMMIT" | cut -c1-9)" \
 && ninja -C build \
 && cmake --install build --prefix /usr/local \
 && strip /usr/local/bin/llarpd \
 && /usr/local/bin/llarpd --version

# the Debian packages providing llarpd's shared libraries, for the runtime image
RUN ldd /usr/local/bin/llarpd | awk '/=> \// {print $3}' | xargs -r realpath \
      | while read -r lib; do dpkg -S "$lib" 2>/dev/null || dpkg -S "${lib#/usr}"; done \
      | cut -d: -f1 | sort -u > /llarpd-deps.txt \
 && cat /llarpd-deps.txt


FROM debian:trixie-slim

COPY --from=build /llarpd-deps.txt /tmp/llarpd-deps.txt
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      $(cat /tmp/llarpd-deps.txt) python3 iproute2 nftables procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* /tmp/llarpd-deps.txt

COPY --from=build /usr/local/bin/llarpd /usr/local/bin/llarpd
RUN ! ldd /usr/local/bin/llarpd | grep "not found" && llarpd --version

COPY llarp_core.py umbrel/umbrel_node.py umbrel/umbrel_bridge.py /app/
COPY umbrel/web /app/web
COPY umbrel/bootstrap /app/bootstrap

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LLARP_DATA=/data
LABEL org.opencontainers.image.source="https://github.com/dwarner5522/llarp-control" \
      org.opencontainers.image.description="LLARP (llarpd) for Umbrel: router or client node with a web control page" \
      org.opencontainers.image.licenses="GPL-3.0-only"
VOLUME /data
ENTRYPOINT ["python3"]
CMD ["/app/umbrel_node.py"]
