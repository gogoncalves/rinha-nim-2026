
FROM --platform=linux/amd64 alpine:3.20 AS builder

RUN apk add --no-cache nim gcc musl-dev curl tar gzip ca-certificates

WORKDIR /src

COPY tools ./tools

ARG NIMFLAGS="-d:release -d:danger --mm:arc --threads:on --opt:speed --stackTrace:off --lineTrace:off \
  --passC:-O3 --passC:-march=haswell --passC:-mavx2 --passC:-flto --passL:-flto --passL:-static --passL:-lpthread"

# Use prebuilt index.bin from build context (extracted from prior image) to avoid
# rebuilding the index on every change. Falls back to the build step if missing.
COPY index.bin /index.bin

COPY src ./src

RUN nim c ${NIMFLAGS} -o:/server src/server.nim
# Pure-C LB: static, stripped, AVX2-friendly. Replaces the Nim lb on v5.
RUN gcc -O3 -static -march=haswell -flto -s -o /lb src/lb.c
RUN strip /server /lb || true

FROM --platform=linux/amd64 scratch
COPY --from=builder /server /server
COPY --from=builder /lb /lb
COPY --from=builder /index.bin /data/index.bin
ENV INDEX_PATH=/data/index.bin
EXPOSE 9999
ENTRYPOINT ["/server"]
