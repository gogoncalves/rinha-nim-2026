
import os, strutils, streams

const
  DIMS = 14
  PADDED_DIMS = 16
  LANES = 8
  QUANT_SCALE: float32 = 10000.0
  QUANT_MAX: float32 = 10000.0
  MAGIC: uint32 = 0x52494E48'u32
  VERSION: uint32 = 4'u32
  K = 4096
  KMEANS_ITERS = 8

type Header {.packed.} = object
  magic: uint32
  version: uint32
  k: uint32
  n: uint32
  n_blocks: uint32
  scale: float32
  reserved: array[40, uint8]

proc xorShift(state: var uint64): uint64 =
  var x = state
  x = x xor (x shl 13)
  x = x xor (x shr 7)
  x = x xor (x shl 17)
  state = x
  x

proc isSpace(c: char): bool {.inline.} = c == ' ' or c == '\t' or c == '\r' or c == '\n'

proc parseFloatFast(s: string, i: var int): float32 =
  var sign: float64 = 1.0
  if i < s.len and s[i] == '-': sign = -1.0; inc i
  elif i < s.len and s[i] == '+': inc i
  var num: float64 = 0
  while i < s.len and s[i] >= '0' and s[i] <= '9':
    num = num * 10 + float64(ord(s[i]) - ord('0'))
    inc i
  if i < s.len and s[i] == '.':
    inc i
    var frac: float64 = 0
    var dvr: float64 = 1
    while i < s.len and s[i] >= '0' and s[i] <= '9':
      frac = frac * 10 + float64(ord(s[i]) - ord('0'))
      dvr *= 10
      inc i
    num += frac / dvr
  if i < s.len and (s[i] == 'e' or s[i] == 'E'):
    inc i
    var esign = 1
    if i < s.len and s[i] == '-': esign = -1; inc i
    elif i < s.len and s[i] == '+': inc i
    var e = 0
    while i < s.len and s[i] >= '0' and s[i] <= '9':
      e = e * 10 + (ord(s[i]) - ord('0'))
      inc i
    var m: float64 = 1
    while e > 0:
      m *= 10
      dec e
    if esign < 0: num /= m else: num *= m
  result = float32(sign * num)

proc parseAll(buf: string, vecs: var seq[array[DIMS, float32]], labels: var seq[uint8]) =
  var i = 0
  while i < buf.len and buf[i] != '[': inc i
  if i >= buf.len: return
  inc i
  while i < buf.len:
    while i < buf.len and isSpace(buf[i]): inc i
    if i >= buf.len or buf[i] == ']': return
    if buf[i] != '{':
      inc i
      continue
    inc i
    var v: array[DIMS, float32]
    var lab: uint8 = 0
    var gotV = false
    var gotL = false
    while i < buf.len and buf[i] != '}':
      while i < buf.len and (isSpace(buf[i]) or buf[i] == ','): inc i
      if i >= buf.len or buf[i] == '}': break
      if buf[i] != '"':
        inc i
        continue
      inc i
      let ks = i
      while i < buf.len and buf[i] != '"': inc i
      let key = buf.substr(ks, i - 1)
      if i < buf.len: inc i
      while i < buf.len and (isSpace(buf[i]) or buf[i] == ':'): inc i
      if key == "vector":
        while i < buf.len and buf[i] != '[': inc i
        if i >= buf.len: break
        inc i
        var k = 0
        while i < buf.len and k < DIMS:
          while i < buf.len and (isSpace(buf[i]) or buf[i] == ','): inc i
          if buf[i] == ']': break
          v[k] = parseFloatFast(buf, i)
          inc k
        while i < buf.len and buf[i] != ']': inc i
        if i < buf.len: inc i
        gotV = true
      elif key == "label":
        while i < buf.len and buf[i] != '"': inc i
        inc i
        let ls = i
        while i < buf.len and buf[i] != '"': inc i
        let s = buf.substr(ls, i - 1)
        inc i
        lab = if s == "fraud": 1'u8 else: 0'u8
        gotL = true
      else:
        while i < buf.len and isSpace(buf[i]): inc i
        if i < buf.len:
          let c = buf[i]
          if c == '"':
            inc i
            while i < buf.len and buf[i] != '"': inc i
            if i < buf.len: inc i
          elif c == '{' or c == '[':
            let closer = if c == '{': '}' else: ']'
            var depth = 1
            inc i
            while i < buf.len and depth > 0:
              if buf[i] == c: inc depth
              elif buf[i] == closer: dec depth
              inc i
          else:
            while i < buf.len:
              let cc = buf[i]
              if cc == ',' or cc == '}' or cc == ']': break
              inc i
    if i < buf.len: inc i
    if gotV and gotL:
      vecs.add v
      labels.add lab
    while i < buf.len and (isSpace(buf[i]) or buf[i] == ','): inc i

proc dist2(a, b: array[DIMS, float32]): float32 =
  var s: float32 = 0
  for j in 0 ..< DIMS:
    let d = a[j] - b[j]
    s += d * d
  s

proc nearest(centers: seq[array[DIMS, float32]], p: array[DIMS, float32]): uint32 =
  var bestI: uint32 = 0
  var bestD: float32 = float32.high
  for i in 0 ..< centers.len:
    let d = dist2(p, centers[i])
    if d < bestD: bestD = d; bestI = uint32(i)
  bestI

proc roundF32(x: float32): float32 {.inline.} =
  if x >= 0.0'f32: float32(int32(x + 0.5'f32))
  else: float32(int32(x - 0.5'f32))

proc quantize(v: array[DIMS, float32]): array[PADDED_DIMS, int16] =
  for i in 0 ..< DIMS:
    var x = v[i] * QUANT_SCALE
    if x > QUANT_MAX: x = QUANT_MAX
    elif x < -QUANT_MAX: x = -QUANT_MAX
    result[i] = int16(roundF32(x))

proc main() =
  let inPath = getEnv("INPUT", "")
  let outPath = getEnv("OUTPUT", "")
  let maxRecs = parseInt(getEnv("MAX_RECS", "0"))
  if inPath.len == 0 or outPath.len == 0:
    echo "set INPUT=path/to/refs.json OUTPUT=path/to/index.bin [MAX_RECS=n]"
    quit(1)

  echo "reading ", inPath
  var f = open(inPath, fmRead)
  defer: f.close()
  var buf = newStringOfCap(int(f.getFileSize()))
  buf.setLen(int(f.getFileSize()))
  if f.readBuffer(addr buf[0], buf.len) != buf.len:
    echo "short read"
    quit(1)
  echo "size ", buf.len div (1024*1024), " MB"

  var vecs: seq[array[DIMS, float32]] = @[]
  var labels: seq[uint8] = @[]
  parseAll(buf, vecs, labels)
  echo "parsed ", vecs.len, " vecs"
  if maxRecs > 0 and vecs.len > maxRecs:
    vecs.setLen(maxRecs)
    labels.setLen(maxRecs)
    echo "truncated to ", maxRecs
  let n = vecs.len
  if n == 0:
    echo "no vecs"
    quit(1)

  var rng: uint64 = 0xDEADBEEFCAFEBABE'u64
  let k = min(K, n)
  var centers = newSeq[array[DIMS, float32]](k)
  for i in 0 ..< k:
    centers[i] = vecs[int(xorShift(rng) mod uint64(n))]

  for it in 0 ..< KMEANS_ITERS:
    var sums = newSeq[array[DIMS, float64]](k)
    var counts = newSeq[uint32](k)
    for v in vecs:
      let c = int(nearest(centers, v))
      for j in 0 ..< DIMS: sums[c][j] += v[j]
      inc counts[c]
    for i in 0 ..< k:
      if counts[i] > 0:
        let inv = 1.0 / float64(counts[i])
        for j in 0 ..< DIMS:
          centers[i][j] = float32(sums[i][j] * inv)
      else:
        centers[i] = vecs[int(xorShift(rng) mod uint64(n))]
    echo "iter ", it, " done"

  var assignments = newSeq[uint32](n)
  var counts = newSeq[uint32](K)
  for i in 0 ..< n:
    let c = nearest(centers, vecs[i])
    assignments[i] = c
    inc counts[int(c)]

  var blocksPer = newSeq[uint32](K)
  var totalBlocks: uint32 = 0
  for i in 0 ..< K:
    let b = (counts[i] + uint32(LANES) - 1) div uint32(LANES)
    blocksPer[i] = b
    totalBlocks += b

  var blockOffsets = newSeq[uint32](K + 1)
  for i in 0 ..< K:
    blockOffsets[i + 1] = blockOffsets[i] + blocksPer[i]

  var bboxMin = newSeq[array[PADDED_DIMS, int16]](K)
  var bboxMax = newSeq[array[PADDED_DIMS, int16]](K)
  for i in 0 ..< K:
    for j in 0 ..< PADDED_DIMS:
      bboxMin[i][j] = high(int16)
      bboxMax[i][j] = low(int16)

  let codeWords = int(totalBlocks) * PADDED_DIMS * LANES
  var codes = newSeq[int16](codeWords)
  var lbls = newSeq[uint8](int(totalBlocks) * LANES)

  var clusterIdx = newSeq[seq[uint32]](K)
  for i in 0 ..< K: clusterIdx[i] = newSeqOfCap[uint32](counts[i])
  for i in 0 ..< n: clusterIdx[int(assignments[i])].add uint32(i)

  var curBlock = newSeq[uint32](K)
  var curLane = newSeq[uint8](K)
  for i in 0 ..< K: curBlock[i] = blockOffsets[i]

  for c in 0 ..< K:
    for ii in clusterIdx[c]:
      let v = vecs[int(ii)]
      let q = quantize(v)
      for j in 0 ..< PADDED_DIMS:
        if q[j] < bboxMin[c][j]: bboxMin[c][j] = q[j]
        if q[j] > bboxMax[c][j]: bboxMax[c][j] = q[j]
      let bi = int(curBlock[c])
      let lane = int(curLane[c])
      let blockBase = bi * PADDED_DIMS * LANES
      for p in 0 ..< (PADDED_DIMS div 2):
        let pairBase = blockBase + p * LANES * 2
        codes[pairBase + lane * 2] = q[p * 2]
        codes[pairBase + lane * 2 + 1] = q[p * 2 + 1]
      lbls[bi * LANES + lane] = labels[int(ii)]
      inc curLane[c]
      if curLane[c] == uint8(LANES):
        curLane[c] = 0
        inc curBlock[c]

  var centroidsQ = newSeq[array[PADDED_DIMS, int16]](K)
  for i in 0 ..< K:
    if i < k:
      centroidsQ[i] = quantize(centers[i])

  let nCent = (K + LANES - 1) div LANES
  var centroidSoa = newSeq[int16](nCent * PADDED_DIMS * LANES)
  for ci in 0 ..< K:
    let bi = ci div LANES
    let lane = ci mod LANES
    let blockBase = bi * PADDED_DIMS * LANES
    for p in 0 ..< (PADDED_DIMS div 2):
      let pairBase = blockBase + p * LANES * 2
      centroidSoa[pairBase + lane * 2] = centroidsQ[ci][p * 2]
      centroidSoa[pairBase + lane * 2 + 1] = centroidsQ[ci][p * 2 + 1]

  echo "writing ", outPath
  var s = newFileStream(outPath, fmWrite)
  defer: s.close()
  var hdr: Header
  hdr.magic = MAGIC
  hdr.version = VERSION
  hdr.k = uint32(K)
  hdr.n = uint32(n)
  hdr.n_blocks = totalBlocks
  hdr.scale = QUANT_SCALE
  s.writeData(addr hdr, sizeof(Header))
  s.writeData(addr centroidSoa[0], centroidSoa.len * 2)
  s.writeData(addr bboxMin[0], bboxMin.len * PADDED_DIMS * 2)
  s.writeData(addr bboxMax[0], bboxMax.len * PADDED_DIMS * 2)
  s.writeData(addr blockOffsets[0], blockOffsets.len * 4)
  s.writeData(addr counts[0], counts.len * 4)
  if codes.len > 0: s.writeData(addr codes[0], codes.len * 2)
  if lbls.len > 0: s.writeData(addr lbls[0], lbls.len)
  echo "done n=", n, " k=", K, " blocks=", totalBlocks

when isMainModule:
  main()
