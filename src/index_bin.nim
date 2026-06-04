
import posix
import normalize

const
  MAGIC*: uint32 = 0x52494E48'u32
  VERSION*: uint32 = 4'u32
  LANES* = 8
  PAIRS* = (DIMS + 1) div 2
  BLOCK_BYTES* = PADDED_DIMS * LANES * 2

type
  Header* {.packed.} = object
    magic*: uint32
    version*: uint32
    k*: uint32
    n*: uint32
    n_blocks*: uint32
    scale*: float32
    reserved*: array[40, uint8]

  Index* = object
    map_ptr*: pointer
    map_len*: int
    centroids_base*: ptr UncheckedArray[int16]
    n_centroid_blocks*: int
    bbox_min*: ptr UncheckedArray[array[PADDED_DIMS, int16]]
    bbox_max*: ptr UncheckedArray[array[PADDED_DIMS, int16]]
    block_offsets*: ptr UncheckedArray[uint32]
    counts*: ptr UncheckedArray[uint32]
    vectors_base*: ptr UncheckedArray[int16]
    labels*: ptr UncheckedArray[uint8]
    k*: int
    n*: int
    n_blocks*: int

const
  MADV_RANDOM_C* = 1.cint
  MADV_WILLNEED_C* = 3.cint
  MADV_HUGEPAGE_C* = 14.cint

proc madvise(addr1: pointer, length: csize_t, advice: cint): cint
  {.importc: "madvise", header: "<sys/mman.h>".}

when defined(linux):
  const MAP_POPULATE_C = 0x8000.cint
else:
  const MAP_POPULATE_C = 0.cint

proc open*(path: string): Index =
  let fd = posix.open(path.cstring, O_RDONLY)
  if fd < 0:
    raise newException(IOError, "cannot open " & path)
  defer: discard posix.close(fd)
  var st: Stat
  if fstat(fd, st) < 0:
    raise newException(IOError, "fstat failed")
  let size = int(st.st_size)
  let flags = cint(MAP_PRIVATE) or MAP_POPULATE_C
  let p = mmap(nil, size, PROT_READ, flags, fd, 0)
  if p == cast[pointer](-1):
    raise newException(IOError, "mmap failed")

  let base = cast[uint](p)
  let hdr = cast[ptr Header](p)
  if hdr.magic != MAGIC:
    raise newException(ValueError, "bad magic")
  if hdr.version != VERSION:
    raise newException(ValueError, "bad version")

  let k = int(hdr.k)
  let n = int(hdr.n)
  let nb = int(hdr.n_blocks)

  var cur = sizeof(Header)
  let nCent = (k + LANES - 1) div LANES
  let centroidsBase = cast[ptr UncheckedArray[int16]](base + uint(cur))
  cur += nCent * BLOCK_BYTES

  let bmin = cast[ptr UncheckedArray[array[PADDED_DIMS, int16]]](base + uint(cur))
  cur += k * PADDED_DIMS * 2
  let bmax = cast[ptr UncheckedArray[array[PADDED_DIMS, int16]]](base + uint(cur))
  cur += k * PADDED_DIMS * 2

  let offs = cast[ptr UncheckedArray[uint32]](base + uint(cur))
  cur += (k + 1) * 4
  let counts = cast[ptr UncheckedArray[uint32]](base + uint(cur))
  cur += k * 4

  let vectorsBase = cast[ptr UncheckedArray[int16]](base + uint(cur))
  cur += nb * BLOCK_BYTES

  let labels = cast[ptr UncheckedArray[uint8]](base + uint(cur))

  discard madvise(p, csize_t(size), MADV_HUGEPAGE_C)
  discard madvise(p, csize_t(size), MADV_WILLNEED_C)
  discard madvise(p, csize_t(size), MADV_RANDOM_C)

  var acc: uint8 = 0
  var i = 0
  let bp = cast[ptr UncheckedArray[uint8]](p)
  while i < size:
    acc = acc xor bp[i]
    i += 4096
  if acc == 13'u8:
    discard

  result = Index(
    map_ptr: p,
    map_len: size,
    centroids_base: centroidsBase,
    n_centroid_blocks: nCent,
    bbox_min: bmin,
    bbox_max: bmax,
    block_offsets: offs,
    counts: counts,
    vectors_base: vectorsBase,
    labels: labels,
    k: k,
    n: n,
    n_blocks: nb
  )

proc close*(idx: var Index) =
  if idx.map_ptr != nil:
    discard munmap(idx.map_ptr, idx.map_len)
    idx.map_ptr = nil
