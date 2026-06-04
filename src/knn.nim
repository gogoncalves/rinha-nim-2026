
import index_bin, normalize

const
  NPROBE* = 2
  REPAIR_EXTRA* = 32
  MAX_PROBES* = NPROBE + REPAIR_EXTRA
  MAX_K* = 4096
  SEEN_WORDS* = (MAX_K + 63) div 64
  TOP_K* = 5
  REPAIR_MIN*: uint8 = 1
  REPAIR_MAX*: uint8 = 4
  QUANT_SCALE*: float32 = 10000.0
  QUANT_MAX*: float32 = 10000.0

const
  EARLY_DIST_QUANT: int64 = (int64(QUANT_SCALE) * 140) div 1000
  EARLY_DIST*: int64 = EARLY_DIST_QUANT * EARLY_DIST_QUANT * int64(DIMS)

{.compile: "simd.c".}
proc blk_dist_c(vectors: ptr int16, block_idx: csize_t, q: ptr int16, outp: ptr int64) {.importc, cdecl.}
proc blk_dist_prune_c(vectors: ptr int16, block_idx: csize_t, q: ptr int16, threshold: int64, outp: ptr int64): cint {.importc, cdecl.}
proc bbox_lb_c(q: ptr int16, mn: ptr int16, mx: ptr int16): int64 {.importc, cdecl.}

type
  Probe* = object
    cluster*: uint32
    dist*: int64

  ProbeArr* = array[MAX_PROBES, Probe]
  TopArr* = array[TOP_K, int64]
  LabArr* = array[TOP_K, uint8]

const NO_CLUSTER: uint32 = 0xFFFF_FFFF'u32
const INT64_MAX: int64 = 0x7FFF_FFFF_FFFF_FFFF'i64

proc roundF32(x: float32): float32 {.inline.} =
  if x >= 0.0'f32: float32(int32(x + 0.5'f32))
  else: float32(int32(x - 0.5'f32))

proc quantize(v: array[DIMS, float32]): array[PADDED_DIMS, int16] {.inline.} =
  for i in 0 ..< DIMS:
    var x = v[i] * QUANT_SCALE
    if x > QUANT_MAX: x = QUANT_MAX
    elif x < -QUANT_MAX: x = -QUANT_MAX
    result[i] = int16(roundF32(x))

proc heapSiftUp(heap: var ProbeArr, start: int) {.inline.} =
  var i = start
  while i > 0:
    let parent = (i - 1) shr 1
    if heap[i].dist > heap[parent].dist:
      swap(heap[i], heap[parent])
      i = parent
    else:
      break

proc heapSiftDown(heap: var ProbeArr, start, size: int) {.inline.} =
  var i = start
  while true:
    let left = 2 * i + 1
    let right = 2 * i + 2
    var largest = i
    if left < size and heap[left].dist > heap[largest].dist: largest = left
    if right < size and heap[right].dist > heap[largest].dist: largest = right
    if largest == i: break
    swap(heap[i], heap[largest])
    i = largest

proc insertProbe(probes: var ProbeArr, count: var int, cluster: uint32, dist: int64) {.inline.} =
  if count < MAX_PROBES:
    probes[count] = Probe(cluster: cluster, dist: dist)
    heapSiftUp(probes, count)
    inc count
    return
  if dist >= probes[0].dist: return
  probes[0] = Probe(cluster: cluster, dist: dist)
  heapSiftDown(probes, 0, MAX_PROBES)

proc heapToSorted(probes: var ProbeArr, count: int) {.inline.} =
  var n = count
  while n > 1:
    dec n
    swap(probes[0], probes[n])
    heapSiftDown(probes, 0, n)

proc insertBest(dist: int64, label: uint8, best_d: var TopArr, best_l: var LabArr) {.inline.} =
  if dist >= best_d[TOP_K - 1]: return
  var pos = TOP_K - 1
  while pos > 0 and dist < best_d[pos - 1]:
    best_d[pos] = best_d[pos - 1]
    best_l[pos] = best_l[pos - 1]
    dec pos
  best_d[pos] = dist
  best_l[pos] = label

proc scanCluster(idx: ptr Index, q: ptr int16, cluster: uint32,
                 best_d: var TopArr, best_l: var LabArr) {.inline.} =
  let startBlk = int(idx.block_offsets[int(cluster)])
  let endBlk = int(idx.block_offsets[int(cluster) + 1])
  let total = idx.counts[int(cluster)]
  if total == 0'u32: return

  var dists: array[LANES, int64]
  var blk = startBlk
  var processed: uint32 = 0
  while blk < endBlk:
    let threshold = best_d[TOP_K - 1]
    let ok = blk_dist_prune_c(
      cast[ptr int16](addr idx.vectors_base[0]),
      csize_t(blk), q, threshold,
      cast[ptr int64](addr dists[0]))
    let laneN = min(uint32(LANES), total - processed)
    processed += laneN
    if ok != 0:
      let labBase = blk * LANES
      var lane: uint32 = 0
      while lane < laneN:
        let d = dists[int(lane)]
        if d < best_d[TOP_K - 1]:
          let label = idx.labels[labBase + int(lane)]
          insertBest(d, label, best_d, best_l)
        inc lane
    inc blk

proc repairFast(idx: ptr Index, q: ptr int16, probes: var ProbeArr, probeCount: int,
                best_d: var TopArr, best_l: var LabArr) {.inline.} =
  var pi = NPROBE
  while pi < probeCount:
    let p = probes[pi]
    if p.cluster == NO_CLUSTER: break
    let lb = bbox_lb_c(q,
      cast[ptr int16](addr idx.bbox_min[int(p.cluster)][0]),
      cast[ptr int16](addr idx.bbox_max[int(p.cluster)][0]))
    if lb >= best_d[TOP_K - 1]:
      inc pi
      continue
    scanCluster(idx, q, p.cluster, best_d, best_l)
    var frauds: uint8 = 0
    for j in 0 ..< TOP_K: frauds += best_l[j]
    if frauds < REPAIR_MIN or frauds > REPAIR_MAX:
      if best_d[TOP_K - 1] <= EARLY_DIST: break
    inc pi

proc repairFull(idx: ptr Index, q: ptr int16, probes: var ProbeArr, probeCount: int,
                best_d: var TopArr, best_l: var LabArr) {.inline.} =
  var seen: array[SEEN_WORDS, uint64]
  for j in 0 ..< probeCount:
    let p = probes[j]
    if p.cluster == NO_CLUSTER: break
    let w = int(p.cluster) shr 6
    let b = int(p.cluster) and 63
    if w < SEEN_WORDS: seen[w] = seen[w] or (1'u64 shl b)
  var ci: uint32 = 0
  while int(ci) < idx.k:
    if idx.counts[int(ci)] == 0'u32:
      inc ci
      continue
    let w = int(ci) shr 6
    let b = int(ci) and 63
    if ((seen[w] shr b) and 1'u64) != 0'u64:
      inc ci
      continue
    let lb = bbox_lb_c(q,
      cast[ptr int16](addr idx.bbox_min[int(ci)][0]),
      cast[ptr int16](addr idx.bbox_max[int(ci)][0]))
    if lb < best_d[TOP_K - 1]:
      scanCluster(idx, q, ci, best_d, best_l)
    inc ci

proc score*(idx: ptr Index, v: array[DIMS, float32]): uint32 =
  var qq = quantize(v)
  let q = cast[ptr int16](addr qq[0])

  var probes: ProbeArr
  for i in 0 ..< MAX_PROBES:
    probes[i] = Probe(cluster: NO_CLUSTER, dist: INT64_MAX)
  var probeCount = 0

  var dists: array[LANES, int64]
  var cb = 0
  while cb < idx.n_centroid_blocks:
    blk_dist_c(cast[ptr int16](addr idx.centroids_base[0]), csize_t(cb), q,
               cast[ptr int64](addr dists[0]))
    let ciBase = uint32(cb * LANES)
    let laneMax = min(uint32(LANES), uint32(idx.k) - ciBase)
    var lane: uint32 = 0
    while lane < laneMax:
      let ci = ciBase + lane
      if idx.counts[int(ci)] != 0'u32:
        insertProbe(probes, probeCount, ci, dists[int(lane)])
      inc lane
    inc cb
  heapToSorted(probes, probeCount)

  var best_d: TopArr
  var best_l: LabArr
  for j in 0 ..< TOP_K: best_d[j] = INT64_MAX

  let nInitial = min(NPROBE, probeCount)
  for pi in 0 ..< nInitial:
    scanCluster(idx, q, probes[pi].cluster, best_d, best_l)

  var frauds: uint32 = 0
  for j in 0 ..< TOP_K: frauds += uint32(best_l[j])

  let unanimous = frauds == 0'u32 or frauds == uint32(TOP_K)
  let tight = best_d[TOP_K - 1] <= EARLY_DIST
  if unanimous and tight:
    return frauds

  repairFast(idx, q, probes, probeCount, best_d, best_l)
  frauds = 0
  for j in 0 ..< TOP_K: frauds += uint32(best_l[j])

  if frauds >= uint32(REPAIR_MIN) and frauds <= uint32(REPAIR_MAX):
    repairFull(idx, q, probes, probeCount, best_d, best_l)
    frauds = 0
    for j in 0 ..< TOP_K: frauds += uint32(best_l[j])

  result = frauds
