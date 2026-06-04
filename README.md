rinha de backend 2026 em nim.

ivf k=4096 nprobe=2 com early-exit, repair_fast + repair_full bbox-lb. soa pair-packed int16, avx2 intrinsics via .c file (`_mm256_madd_epi16`). scm_rights fd-passing lb. std/selectors epoll loop.

build:
```
nim c --opt:speed -d:release -d:danger --mm:arc src/server.nim
docker compose up -d
```
