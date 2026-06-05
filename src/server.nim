
import posix, os, strutils, times
import posix/epoll
import index_bin, normalize, knn, json_parser

when defined(linux):
  proc accept4(sockfd: cint, addr1: ptr SockAddr, addrlen: ptr SockLen, flags: cint): cint
    {.importc: "accept4", header: "<sys/socket.h>".}
else:
  proc accept4(sockfd: cint, addr1: ptr SockAddr, addrlen: ptr SockLen, flags: cint): cint =
    var alen: SockLen
    let p = addrlen
    if p == nil:
      alen = 0
      result = posix.accept(SocketHandle(sockfd), addr1, addr alen).cint
    else:
      result = posix.accept(SocketHandle(sockfd), addr1, p).cint
    if result >= 0:
      let cur = fcntl(result, F_GETFL, 0)
      if cur >= 0: discard fcntl(result, F_SETFL, cur or O_NONBLOCK)
      let curfd = fcntl(result, F_GETFD, 0)
      if curfd >= 0: discard fcntl(result, F_SETFD, curfd or FD_CLOEXEC)

when defined(linux):
  const SOCK_NONBLOCK_C = 0o4000.cint
  const SOCK_CLOEXEC_C = 0o2000000.cint
else:
  const SOCK_NONBLOCK_C = 0.cint
  const SOCK_CLOEXEC_C = 0.cint

const
  MAX_CONNS = 1024
  BUF_SIZE = 8192

type
  Conn = object
    fd: cint
    inLen: uint32
    outLen: uint32
    outPos: uint32
    outPtr: ptr UncheckedArray[char]
    inBuf: array[BUF_SIZE, char]

# Zero-copy pre-baked HTTP responses. Static bytes — `respond` returns
# a (ptr, len) pair so the hot path never allocates or copies a string.
const
  READY_S = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok"
  NOT_FOUND_S = "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n"
  APPROVED_HDR = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 35\r\nconnection: keep-alive\r\n\r\n"
  DENIED_HDR = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 36\r\nconnection: keep-alive\r\n\r\n"
  S0 = APPROVED_HDR & "{\"approved\":true,\"fraud_score\":0.0}"
  S1 = APPROVED_HDR & "{\"approved\":true,\"fraud_score\":0.2}"
  S2 = APPROVED_HDR & "{\"approved\":true,\"fraud_score\":0.4}"
  S3 = DENIED_HDR   & "{\"approved\":false,\"fraud_score\":0.6}"
  S4 = DENIED_HDR   & "{\"approved\":false,\"fraud_score\":0.8}"
  S5 = DENIED_HDR   & "{\"approved\":false,\"fraud_score\":1.0}"

# Store responses as long-lived heap-allocated buffers with stable addresses.
# Nim string literals at module scope point at static rodata in C, but using
# a global var array of cstrings + length table makes the hot path branchless.
type
  RespEntry = object
    p: ptr UncheckedArray[char]
    n: uint32

var
  gReady: RespEntry
  gNotFound: RespEntry
  gScores: array[6, RespEntry]

proc initResponses() =
  proc bake(s: string): RespEntry =
    let n = s.len
    # Allocate stable memory; never freed.
    let p = cast[ptr UncheckedArray[char]](alloc(n))
    copyMem(p, unsafeAddr s[0], n)
    RespEntry(p: p, n: uint32(n))
  gReady = bake(READY_S)
  gNotFound = bake(NOT_FOUND_S)
  gScores[0] = bake(S0)
  gScores[1] = bake(S1)
  gScores[2] = bake(S2)
  gScores[3] = bake(S3)
  gScores[4] = bake(S4)
  gScores[5] = bake(S5)


type
  HttpMethod = enum hmGetReady, hmPostScore, hmOther
  Parsed = object
    meth: HttpMethod
    body: ptr UncheckedArray[char]
    bodyLen: int
    consumed: int

  ParseRes = enum prOk, prIncomplete, prBad

proc asciiEqlIgnoreCase(a: ptr UncheckedArray[char], aLen: int, b: string): bool =
  if aLen != b.len: return false
  for i in 0 ..< aLen:
    let x = a[i]
    let y = b[i]
    let xl = if x >= 'A' and x <= 'Z': char(ord(x) + 32) else: x
    let yl = if y >= 'A' and y <= 'Z': char(ord(y) + 32) else: y
    if xl != yl: return false
  true

proc findCRLF2(buf: ptr UncheckedArray[char], n: int): int =
  var i = 0
  while i + 3 < n:
    if buf[i] == '\r' and buf[i+1] == '\n' and buf[i+2] == '\r' and buf[i+3] == '\n':
      return i
    inc i
  -1

proc findContentLength(hdrs: ptr UncheckedArray[char], n: int): int =
  var i = 0
  result = -1
  while i < n:
    var nl = i
    while nl < n and hdrs[nl] != '\n': inc nl
    if nl >= n: return -1
    let lineEnd = if nl > i and hdrs[nl - 1] == '\r': nl - 1 else: nl
    let lineLen = lineEnd - i
    if lineLen >= 15:
      if asciiEqlIgnoreCase(cast[ptr UncheckedArray[char]](addr hdrs[i]), 15, "content-length:"):
        var v = 0
        var j = i + 15
        while j < lineEnd and (hdrs[j] == ' ' or hdrs[j] == '\t'): inc j
        while j < lineEnd and hdrs[j] >= '0' and hdrs[j] <= '9':
          v = v * 10 + (ord(hdrs[j]) - ord('0'))
          inc j
        return v
    i = nl + 1
  result = -1

proc startsWith(buf: ptr UncheckedArray[char], n: int, lit: string): bool {.inline.} =
  if n < lit.len: return false
  for i in 0 ..< lit.len:
    if buf[i] != lit[i]: return false
  true

proc parseReq(buf: ptr UncheckedArray[char], n: int, dst: var Parsed): ParseRes =
  if n < 16: return prIncomplete
  if startsWith(buf, n, "POST /fraud-score"):
    let hdrEnd = findCRLF2(buf, n)
    if hdrEnd < 0: return prIncomplete
    let cl = findContentLength(buf, hdrEnd + 2)
    if cl < 0: return prBad
    let bodyStart = hdrEnd + 4
    let total = bodyStart + cl
    if n < total: return prIncomplete
    dst.meth = hmPostScore
    dst.body = cast[ptr UncheckedArray[char]](addr buf[bodyStart])
    dst.bodyLen = cl
    dst.consumed = total
    return prOk
  if startsWith(buf, n, "GET /ready"):
    let sep = findCRLF2(buf, n)
    if sep < 0: return prIncomplete
    dst.meth = hmGetReady
    dst.body = nil
    dst.bodyLen = 0
    dst.consumed = sep + 4
    return prOk
  let sep = findCRLF2(buf, n)
  if sep < 0: return prIncomplete
  dst.meth = hmOther
  dst.body = nil
  dst.bodyLen = 0
  dst.consumed = sep + 4
  return prOk

proc respond(idx: ptr Index, req: Parsed): RespEntry {.inline.} =
  case req.meth
  of hmGetReady: return gReady
  of hmOther: return gNotFound
  of hmPostScore:
    var payload: Payload
    try:
      payload = parse(req.body, req.bodyLen)
    except CatchableError:
      return gScores[0]
    let v = vectorize(addr payload)
    let frauds = idx.score(v)
    let i = if frauds > 5'u32: 5 else: int(frauds)
    return gScores[i]


type
  HandlerKind = enum hkListenTcp, hkCtrlAccept, hkCtrlConn, hkClient

type
  Worker = object
    idx: ptr Index
    conns: array[MAX_CONNS, Conn]
    freeIdx: array[MAX_CONNS, uint16]
    freeCount: int
    ctrlConnFd: cint
    ctrlListenFd: cint
    legacyListenFd: cint
    epfd: cint
    ctrlPath: string
    sockPath: string

proc packTag(kind: HandlerKind, ci: int): uint64 {.inline.} =
  (uint64(kind.ord) shl 32) or uint64(uint32(ci))

proc unpackKind(tag: uint64): HandlerKind {.inline.} =
  HandlerKind((tag shr 32) and 0xFFFFFFFF'u64)

proc unpackCi(tag: uint64): int {.inline.} =
  int(uint32(tag and 0xFFFFFFFF'u64))

proc epollAdd(w: var Worker, fd: cint, events: uint32, tag: uint64): cint {.inline.} =
  var ev: EpollEvent
  ev.events = events
  ev.data.u64 = tag
  epoll_ctl(w.epfd, EPOLL_CTL_ADD.cint, fd, addr ev)

proc epollMod(w: var Worker, fd: cint, events: uint32, tag: uint64): cint {.inline.} =
  var ev: EpollEvent
  ev.events = events
  ev.data.u64 = tag
  epoll_ctl(w.epfd, EPOLL_CTL_MOD.cint, fd, addr ev)

proc epollDel(w: var Worker, fd: cint): cint {.inline.} =
  epoll_ctl(w.epfd, EPOLL_CTL_DEL.cint, fd, nil)

const
  EVENTS_READ = uint32(EPOLLIN) or uint32(EPOLLET) or uint32(EPOLLRDHUP)
  EVENTS_RW = uint32(EPOLLIN) or uint32(EPOLLOUT) or uint32(EPOLLET) or uint32(EPOLLRDHUP)

proc onRecv(w: var Worker, ci: int)

proc closeConn(w: var Worker, ci: int) =
  let c = addr w.conns[ci]
  if c.fd >= 0:
    discard epollDel(w, c.fd)
    discard posix.close(c.fd)
    c.fd = -1
  c.inLen = 0
  c.outPtr = nil
  c.outLen = 0
  c.outPos = 0
  w.freeIdx[w.freeCount] = uint16(ci)
  inc w.freeCount

proc shiftBuf(c: var Conn, consumed: int) {.inline.} =
  if consumed >= int(c.inLen):
    c.inLen = 0
    return
  let rem = int(c.inLen) - consumed
  moveMem(addr c.inBuf[0], addr c.inBuf[consumed], rem)
  c.inLen = uint32(rem)

proc drainSendNow(c: var Conn): bool =
  while c.outPos < c.outLen:
    let sent = posix.send(SocketHandle(c.fd),
      addr c.outPtr[int(c.outPos)],
      int(c.outLen) - int(c.outPos), 0.cint)
    if sent <= 0:
      return false
    c.outPos += uint32(sent)
  true

proc addClientFd(w: var Worker, cfd: cint) =
  if w.freeCount == 0:
    discard posix.close(cfd)
    return
  let cur = fcntl(cfd, F_GETFL, 0)
  if cur >= 0: discard fcntl(cfd, F_SETFL, cur or O_NONBLOCK)
  dec w.freeCount
  let ci = int(w.freeIdx[w.freeCount])
  w.conns[ci].fd = cfd
  w.conns[ci].inLen = 0
  w.conns[ci].outPtr = nil
  w.conns[ci].outLen = 0
  w.conns[ci].outPos = 0
  let rc = epollAdd(w, cfd, EVENTS_READ, packTag(hkClient, ci))
  if rc < 0:
    discard posix.close(cfd)
    w.conns[ci].fd = -1
    w.freeIdx[w.freeCount] = uint16(ci)
    inc w.freeCount
    return
  onRecv(w, ci)

proc addClientFdWithBytes(w: var Worker, cfd: cint, src: ptr uint8, srcLen: int) =
  if w.freeCount == 0:
    discard posix.close(cfd)
    return
  let cur = fcntl(cfd, F_GETFL, 0)
  if cur >= 0: discard fcntl(cfd, F_SETFL, cur or O_NONBLOCK)
  dec w.freeCount
  let ci = int(w.freeIdx[w.freeCount])
  let c = addr w.conns[ci]
  c.fd = cfd
  c.outPtr = nil
  c.outLen = 0
  c.outPos = 0
  let copyLen = min(srcLen, BUF_SIZE)
  if copyLen > 0:
    copyMem(addr c.inBuf[0], src, copyLen)
  c.inLen = uint32(copyLen)
  let rc = epollAdd(w, cfd, EVENTS_READ, packTag(hkClient, ci))
  if rc < 0:
    discard posix.close(cfd)
    c.fd = -1
    c.inLen = 0
    w.freeIdx[w.freeCount] = uint16(ci)
    inc w.freeCount
    return
  onRecv(w, ci)

proc onRecv(w: var Worker, ci: int) =
  let c = addr w.conns[ci]
  while c.inLen > 0:
    var req: Parsed
    let r = parseReq(cast[ptr UncheckedArray[char]](addr c.inBuf[0]), int(c.inLen), req)
    case r
    of prIncomplete: break
    of prBad:
      closeConn(w, ci)
      return
    of prOk:
      let resp = respond(w.idx, req)
      c.outPtr = resp.p
      c.outLen = resp.n
      c.outPos = 0
      if not drainSendNow(c[]):
        shiftBuf(c[], req.consumed)
        discard epollMod(w, c.fd, EVENTS_RW, packTag(hkClient, ci))
        return
      shiftBuf(c[], req.consumed)
  while true:
    if c.inLen >= uint32(BUF_SIZE):
      closeConn(w, ci)
      return
    let got = posix.recv(SocketHandle(c.fd),
      addr c.inBuf[int(c.inLen)],
      BUF_SIZE - int(c.inLen), 0.cint)
    if got < 0:
      let e = errno
      if e == EAGAIN or e == EWOULDBLOCK: return
      closeConn(w, ci)
      return
    if got == 0:
      closeConn(w, ci)
      return
    c.inLen += uint32(got)
    while c.inLen > 0:
      var req: Parsed
      let r = parseReq(cast[ptr UncheckedArray[char]](addr c.inBuf[0]), int(c.inLen), req)
      case r
      of prIncomplete: break
      of prBad:
        closeConn(w, ci)
        return
      of prOk:
        let resp = respond(w.idx, req)
        c.outPtr = resp.p
        c.outLen = resp.n
        c.outPos = 0
        if not drainSendNow(c[]):
          shiftBuf(c[], req.consumed)
          discard epollMod(w, c.fd, EVENTS_RW, packTag(hkClient, ci))
          return
        shiftBuf(c[], req.consumed)

proc onSend(w: var Worker, ci: int) =
  let c = addr w.conns[ci]
  if drainSendNow(c[]):
    discard epollMod(w, c.fd, EVENTS_READ, packTag(hkClient, ci))

proc acceptAllTcp(w: var Worker) =
  while true:
    let cfd = accept4(w.legacyListenFd, nil, nil, SOCK_NONBLOCK_C or SOCK_CLOEXEC_C)
    if cfd < 0: return
    addClientFd(w, cfd)


const
  SCM_RIGHTS_C = 1.cint
  SOL_SOCKET_C = 1.cint
  MSG_CMSG_CLOEXEC_C = 0x40000000.cint
  MSG_DONTWAIT_C = 0x40.cint

type
  Cmsghdr {.importc: "struct cmsghdr", header: "<sys/socket.h>".} = object

proc cmsgAlign(len: int): int {.inline.} =
  let a = sizeof(int)
  (len + a - 1) and not (a - 1)

proc cmsgSpace(len: int): int {.inline.} =
  cmsgAlign(len) + cmsgAlign(16)

type
  CmsghdrPort = object
    len: csize_t
    level: cint
    typ: cint

type
  Iovec_t {.importc: "struct iovec", header: "<sys/uio.h>".} = object
    iov_base: pointer
    iov_len: csize_t

type
  Msghdr_t {.importc: "struct msghdr", header: "<sys/socket.h>".} = object
    msg_name: pointer
    msg_namelen: cuint
    msg_iov: ptr Iovec_t
    msg_iovlen: csize_t
    msg_control: pointer
    msg_controllen: csize_t
    msg_flags: cint

proc recvmsg_c(sockfd: cint, msg: ptr Msghdr_t, flags: cint): clong
  {.importc: "recvmsg", header: "<sys/socket.h>".}

const CTRL_LEN = 64
const MAX_PREFIX = 4096

proc onCtrlRecv(w: var Worker) =
  while true:
    var lenLE: uint16 = 0
    var prefixBuf {.noinit.}: array[MAX_PREFIX, uint8]
    var iov: array[2, Iovec_t]
    iov[0].iov_base = addr lenLE
    iov[0].iov_len = csize_t(sizeof(uint16))
    iov[1].iov_base = addr prefixBuf[0]
    iov[1].iov_len = csize_t(MAX_PREFIX)
    var ctrlBuf {.noinit.}: array[CTRL_LEN, uint8]
    var msg: Msghdr_t
    msg.msg_name = nil
    msg.msg_namelen = 0
    msg.msg_iov = addr iov[0]
    msg.msg_iovlen = 2
    msg.msg_control = addr ctrlBuf[0]
    msg.msg_controllen = csize_t(CTRL_LEN)
    msg.msg_flags = 0
    let r = recvmsg_c(w.ctrlConnFd, addr msg, MSG_CMSG_CLOEXEC_C or MSG_DONTWAIT_C)
    if r <= 0:
      let e = errno
      if e == EAGAIN or e == EWOULDBLOCK: return
      discard epollDel(w, w.ctrlConnFd)
      discard posix.close(w.ctrlConnFd)
      w.ctrlConnFd = -1
      return
    let cmsg = cast[ptr CmsghdrPort](addr ctrlBuf[0])
    if cmsg.level != SOL_SOCKET_C or cmsg.typ != SCM_RIGHTS_C: continue
    let dataOff = cmsgAlign(sizeof(CmsghdrPort))
    let fdPtr = cast[ptr cint](addr ctrlBuf[dataOff])
    let cfd = fdPtr[]
    var payloadLen = 0
    if r >= clong(sizeof(uint16)):
      let declared = int(lenLE)
      let bodyAvail = int(r) - sizeof(uint16)
      payloadLen = min(declared, bodyAvail)
      if payloadLen < 0: payloadLen = 0
    addClientFdWithBytes(w, cfd, addr prefixBuf[0], payloadLen)

proc acceptCtrl(w: var Worker) =
  var addr_un {.noinit.}: SockAddr
  var alen: SockLen = 0
  if w.ctrlConnFd >= 0:
    let c = accept4(w.ctrlListenFd, addr addr_un, addr alen, SOCK_CLOEXEC_C)
    if c >= 0: discard posix.close(c)
    return
  let c = accept4(w.ctrlListenFd, addr addr_un, addr alen, SOCK_NONBLOCK_C or SOCK_CLOEXEC_C)
  if c < 0: return
  w.ctrlConnFd = c
  if epollAdd(w, c, EVENTS_READ, packTag(hkCtrlConn, 0)) < 0:
    discard posix.close(c)
    w.ctrlConnFd = -1


const SOCK_SEQPACKET_C = 5.cint

proc bindUdsListener(path: string, sockType: cint): cint =
  discard unlink(path.cstring)
  let fd = socket(AF_UNIX, sockType or SOCK_NONBLOCK_C or SOCK_CLOEXEC_C, 0)
  if cint(fd) < 0: raise newException(OSError, "socket failed")
  var sa: Sockaddr_un
  sa.sun_family = TSa_Family(AF_UNIX)
  let n = min(path.len, sa.sun_path.len - 1)
  for i in 0 ..< n: sa.sun_path[i] = path[i]
  sa.sun_path[n] = '\x00'
  let slen = SockLen(sizeof(Sockaddr_un.sun_family) + n + 1)
  if bindSocket(fd, cast[ptr SockAddr](addr sa), slen) < 0:
    raise newException(OSError, "bind failed: " & path)
  if listen(fd, 8) < 0:
    raise newException(OSError, "listen failed")
  discard chmod(path.cstring, 0o666)
  return cint(fd)

proc setNonBlock(fd: cint) =
  let cur = fcntl(fd, F_GETFL, 0)
  if cur >= 0: discard fcntl(fd, F_SETFL, cur or O_NONBLOCK)

proc openTcpListener(port: uint16): cint =
  let fd = socket(AF_INET, SOCK_STREAM or SOCK_NONBLOCK_C or SOCK_CLOEXEC_C, 0)
  if cint(fd) < 0: raise newException(OSError, "socket failed")
  setNonBlock(cint(fd))
  var one: cint = 1
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, addr one, SockLen(sizeof(one)))
  var sa: Sockaddr_in
  sa.sin_family = TSa_Family(AF_INET)
  sa.sin_port = posix.htons(port)
  sa.sin_addr.s_addr = 0
  if bindSocket(fd, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) < 0:
    raise newException(OSError, "bind tcp failed")
  if listen(fd, 512) < 0:
    raise newException(OSError, "listen tcp failed")
  return cint(fd)


const
  MCL_CURRENT_C = 1.cint
  MCL_FUTURE_C = 2.cint

proc mlockall_c(flags: cint): cint {.importc: "mlockall", header: "<sys/mman.h>".}

# prctl(PR_SET_TIMERSLACK, 1) — shrink scheduler wake-up jitter from default
# 50us → 1ns. Best-effort; a process can always tighten its own slack.
const PR_SET_TIMERSLACK_C = 29.cint
proc prctl_c(option: cint, arg2: culong, arg3: culong, arg4: culong, arg5: culong): cint
  {.importc: "prctl", header: "<sys/prctl.h>".}

# sched_setscheduler(SCHED_FIFO, prio) — wake above SCHED_OTHER on IO.
# Best-effort; needs CAP_SYS_NICE or rtprio ulimit. EPERM ignored.
const SCHED_FIFO_C = 1.cint
type SchedParam_c = object
  sched_priority: cint
proc sched_setscheduler_c(pid: cint, policy: cint, param: ptr SchedParam_c): cint
  {.importc: "sched_setscheduler", header: "<sched.h>".}


# pthread bindings (musl/glibc compatible).
type
  PthreadT {.importc: "pthread_t", header: "<pthread.h>".} = uint64
  PthreadAttrT {.importc: "pthread_attr_t", header: "<pthread.h>".} = object
    opaque: array[64, byte]

proc pthread_create(thread: ptr PthreadT, attr: pointer,
                    start_routine: proc (a: pointer): pointer {.cdecl.},
                    arg: pointer): cint {.importc: "pthread_create", header: "<pthread.h>".}

proc pthread_join(thread: PthreadT, retval: ptr pointer): cint
  {.importc: "pthread_join", header: "<pthread.h>".}

# epoll_pwait2 syscall (Linux 5.11+) for nanosecond precision idle waits.
type
  Timespec_c {.importc: "struct timespec", header: "<time.h>".} = object
    tv_sec: clong
    tv_nsec: clong

proc syscall_c(num: clong): clong {.importc: "syscall", header: "<sys/syscall.h>", varargs.}

when defined(linux):
  const SYS_epoll_pwait2_C = 441.clong
else:
  const SYS_epoll_pwait2_C = 0.clong

proc epollPwait2(epfd: cint, events: ptr EpollEvent, maxev: cint,
                  ts: ptr Timespec_c): cint =
  let r = syscall_c(SYS_epoll_pwait2_C, epfd, events, maxev, ts, 0, 8)
  cint(r)

# CPU pause hint for spin loops.
proc cpuRelax() {.inline.} =
  when defined(amd64) or defined(i386):
    {.emit: ["asm volatile (\"pause\");"].}
  else:
    discard

# Monotonic clock helper (nanoseconds).
proc monoNs(): int64 {.inline.} =
  var ts: Timespec_c
  discard syscall_c(228.clong, 1.clong, addr ts)  # SYS_clock_gettime, CLOCK_MONOTONIC
  return int64(ts.tv_sec) * 1_000_000_000'i64 + int64(ts.tv_nsec)

# Globals for sharing parameters between main and worker threads.
var
  gSpinUs: int64 = 200
  gIdleUs: int64 = 5000


proc setupWorker(w: var Worker, port: uint16) =
  for i in 0 ..< MAX_CONNS:
    w.conns[i].fd = -1
    w.freeIdx[MAX_CONNS - 1 - i] = uint16(i)
  w.freeCount = MAX_CONNS
  w.ctrlConnFd = -1
  w.ctrlListenFd = -1
  w.legacyListenFd = -1

  const EPOLL_CLOEXEC_C = 0o2000000.cint
  w.epfd = epoll_create1(EPOLL_CLOEXEC_C)
  if w.epfd < 0:
    raise newException(OSError, "epoll_create1 failed")

  if w.ctrlPath.len > 0:
    w.ctrlListenFd = bindUdsListener(w.ctrlPath, SOCK_SEQPACKET_C)
    if epollAdd(w, w.ctrlListenFd, EVENTS_READ, packTag(hkCtrlAccept, 0)) < 0:
      raise newException(OSError, "epoll_ctl add ctrl listen failed")
  elif w.sockPath.len > 0:
    w.legacyListenFd = bindUdsListener(w.sockPath, SOCK_STREAM)
    if epollAdd(w, w.legacyListenFd, EVENTS_READ, packTag(hkListenTcp, 0)) < 0:
      raise newException(OSError, "epoll_ctl add listen failed")
  else:
    w.legacyListenFd = openTcpListener(port)
    if epollAdd(w, w.legacyListenFd, EVENTS_READ, packTag(hkListenTcp, 0)) < 0:
      raise newException(OSError, "epoll_ctl add tcp listen failed")

proc runEventLoop(w: var Worker) =
  const MAX_EVENTS = 256
  var events {.noinit.}: array[MAX_EVENTS, EpollEvent]
  let errMask = uint32(EPOLLERR) or uint32(EPOLLHUP) or uint32(EPOLLRDHUP)
  let spinNs = gSpinUs * 1000
  let idleNs = gIdleUs * 1000
  while true:
    # Phase 1: non-blocking epoll_wait — drain anything already ready.
    var n = epoll_wait(w.epfd, addr events[0], MAX_EVENTS.cint, 0.cint)
    if n == 0 and spinNs > 0:
      # Phase 2: busy spin with cpu pause hint until SPIN budget exhausted.
      let deadline = monoNs() + spinNs
      while monoNs() < deadline:
        n = epoll_wait(w.epfd, addr events[0], MAX_EVENTS.cint, 0.cint)
        if n != 0: break
        cpuRelax()
    if n == 0:
      # Phase 3: blocking wait, capped by IDLE budget.
      if idleNs > 0:
        var ts: Timespec_c
        ts.tv_sec = clong(idleNs div 1_000_000_000'i64)
        ts.tv_nsec = clong(idleNs mod 1_000_000_000'i64)
        n = epollPwait2(w.epfd, addr events[0], MAX_EVENTS.cint, addr ts)
        if n < 0 and errno != EINTR:
          # epoll_pwait2 missing (kernel < 5.11) → fall back to blocking
          # epoll_wait with millisecond timeout.
          n = epoll_wait(w.epfd, addr events[0], MAX_EVENTS.cint, cint(idleNs div 1_000_000'i64))
      else:
        n = epoll_wait(w.epfd, addr events[0], MAX_EVENTS.cint, -1.cint)
    if n < 0:
      if errno == EINTR: continue
      break
    for i in 0 ..< n:
      let ev = addr events[i]
      let tag = ev.data.u64
      let kind = unpackKind(tag)
      let ci = unpackCi(tag)
      let mask = ev.events
      case kind
      of hkListenTcp: acceptAllTcp(w)
      of hkCtrlAccept: acceptCtrl(w)
      of hkCtrlConn: onCtrlRecv(w)
      of hkClient:
        if (mask and uint32(EPOLLIN)) != 0: onRecv(w, ci)
        if w.conns[ci].fd >= 0 and (mask and uint32(EPOLLOUT)) != 0: onSend(w, ci)
        if w.conns[ci].fd >= 0 and (mask and errMask) != 0: closeConn(w, ci)

proc workerEntry(arg: pointer): pointer {.cdecl.} =
  let w = cast[ptr Worker](arg)
  try:
    setupWorker(w[], 9999'u16)
    runEventLoop(w[])
  except CatchableError as e:
    stderr.writeLine "[worker] error: ", e.msg
    quit(1)
  return nil

proc resolveWorkerPath(prefix, ctrlEnv, sockEnv: string, wi, nworkers: int):
    tuple[ctrlPath, sockPath: string] =
  ## Compute per-worker control/listen socket paths.
  ## - API_SOCKET_PREFIX=/sock/api1     -> ctrl /sock/api1-wN.sock (always CTRL)
  ## - CTRL_SOCK_PATH=/sock/api1.sock  -> if N=1: keep; else suffix -wN
  ## - SOCK_PATH=/sock/api1.sock       -> if N=1: keep; else suffix -wN
  if prefix.len > 0:
    return (prefix & "-w" & $wi & ".sock", "")
  if ctrlEnv.len > 0:
    if nworkers == 1:
      return (ctrlEnv, "")
    var base = ctrlEnv
    if base.endsWith(".sock"): base = base[0 ..< base.len - 5]
    return (base & "-w" & $wi & ".sock", "")
  if sockEnv.len > 0:
    if nworkers == 1:
      return ("", sockEnv)
    var base = sockEnv
    if base.endsWith(".sock"): base = base[0 ..< base.len - 5]
    return ("", base & "-w" & $wi & ".sock")
  return ("", "")


proc main() =
  let indexPath = getEnv("INDEX_PATH", "/data/index.bin")
  let sockPath = getEnv("SOCK_PATH", "")
  let ctrlPath = getEnv("CTRL_SOCK_PATH", "")
  let prefix = getEnv("API_SOCKET_PREFIX", "")
  let portStr = getEnv("PORT", "9999")
  let port = uint16(parseInt(portStr))

  gSpinUs = int64(parseInt(getEnv("EPOLL_SPIN_US", "200")))
  gIdleUs = int64(parseInt(getEnv("EPOLL_IDLE_US", "5000")))

  let nworkersRaw = parseInt(getEnv("API_WORKERS", "1"))
  let nworkers = if nworkersRaw <= 0: 1 else: nworkersRaw

  initResponses()

  # Best-effort: tighten timer slack to 1ns (default 50us blows the wake-up
  # budget on a 1.4GHz Haswell). Ignore EPERM/ENOSYS.
  discard prctl_c(PR_SET_TIMERSLACK_C, 1.culong, 0.culong, 0.culong, 0.culong)

  # Best-effort: promote to SCHED_FIFO so inbound epoll wake preempts
  # SCHED_OTHER. Needs rtprio ulimit (set in compose). EPERM ignored.
  var rtparam = SchedParam_c(sched_priority: 10.cint)
  discard sched_setscheduler_c(0.cint, SCHED_FIFO_C, addr rtparam)

  var idx = index_bin.open(indexPath)

  # Warmup: bang on the KNN path with pseudo-random vectors so the index pages
  # in, branch predictors and uop caches settle, and the kernel pre-faults the
  # mmaped region before real traffic shows up. Tuneable via WARMUP_MS.
  let warmupMs = parseInt(getEnv("WARMUP_MS", "5000"))
  if warmupMs > 0:
    let t0 = epochTime()
    var rng: uint64 = 0xDEADBEEFCAFEBABE'u64
    var count = 0
    var v: array[DIMS, float32]
    while (epochTime() - t0) * 1000.0 < float(warmupMs):
      for i in 0 ..< DIMS:
        rng = rng xor (rng shl 13)
        rng = rng xor (rng shr 7)
        rng = rng xor (rng shl 17)
        v[i] = float32((rng shr 16) mod 10001'u64) / 10000.0'f32
      discard score(addr idx, v)
      inc count
    stderr.writeLine "[server] warmup ", count, " queries in ", warmupMs, "ms ",
                     "(workers=", nworkers, " spin_us=", gSpinUs, " idle_us=", gIdleUs, ")"
    stderr.flushFile

  if getEnv("MLOCK", "1") != "0":
    discard mlockall_c(MCL_CURRENT_C or MCL_FUTURE_C)

  # Heap-allocate workers — `Worker` is large (>5 MB) and stack-allocating an
  # array of them blows past pthread stacks.
  var workers = cast[ptr UncheckedArray[Worker]](alloc0(sizeof(Worker) * nworkers))
  for i in 0 ..< nworkers:
    workers[i].idx = addr idx
    let (cp, sp) = resolveWorkerPath(prefix, ctrlPath, sockPath, i, nworkers)
    workers[i].ctrlPath = cp
    workers[i].sockPath = sp

  if nworkers == 1:
    discard workerEntry(addr workers[0])
    return

  var threads = newSeq[PthreadT](nworkers - 1)
  for i in 1 ..< nworkers:
    let rc = pthread_create(addr threads[i - 1], nil, workerEntry, addr workers[i])
    if rc != 0:
      raise newException(OSError, "pthread_create failed")
  discard workerEntry(addr workers[0])
  for i in 0 ..< nworkers - 1:
    discard pthread_join(threads[i], nil)

when isMainModule:
  main()
