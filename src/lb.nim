
import posix, os, strutils

when defined(linux):
  const SOCK_NONBLOCK_C = 0o4000.cint
  const SOCK_CLOEXEC_C = 0o2000000.cint
  proc accept4(sockfd: cint, addr1: ptr SockAddr, addrlen: ptr SockLen, flags: cint): cint
    {.importc: "accept4", header: "<sys/socket.h>".}
else:
  const SOCK_NONBLOCK_C = 0.cint
  const SOCK_CLOEXEC_C = 0.cint
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

const
  MAX_BACKENDS = 8
  DEFAULT_BACKLOG = 4096
  DEFAULT_ACCEPT_BATCH = 128

const
  SCM_RIGHTS_C = 1.cint
  SOL_SOCKET_C = 1.cint
  MSG_NOSIGNAL_C = 0x4000.cint
  MSG_DONTWAIT_C = 0x40.cint
  SOCK_SEQPACKET_C = 5.cint
  TCP_NODELAY_C = 1.cint
  TCP_DEFER_ACCEPT_C = 9.cint
  TCP_QUICKACK_C = 12.cint

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

proc sendmsg_c(sockfd: cint, msg: ptr Msghdr_t, flags: cint): clong
  {.importc: "sendmsg", header: "<sys/socket.h>".}

type
  CmsghdrPort = object
    len: csize_t
    level: cint
    typ: cint

proc cmsgAlign(len: int): int {.inline.} =
  let a = sizeof(int)
  (len + a - 1) and not (a - 1)

proc cmsgLen(len: int): int {.inline.} =
  cmsgAlign(sizeof(CmsghdrPort)) + len

proc cmsgSpace(len: int): int {.inline.} =
  cmsgAlign(len) + cmsgAlign(sizeof(CmsghdrPort))

proc connectUds(path: string): cint =
  # Create socket as non-blocking so connect() never hangs when the server
  # has bind()'d the path but not yet listen()'d (race on early startup).
  let fd = socket(AF_UNIX, SOCK_SEQPACKET_C or SOCK_CLOEXEC_C or SOCK_NONBLOCK_C, 0)
  if cint(fd) < 0: raise newException(OSError, "socket failed")
  # Fallback: if SOCK_NONBLOCK_C is 0 on this platform, set O_NONBLOCK via fcntl.
  when SOCK_NONBLOCK_C == 0.cint:
    let curFlags = fcntl(cint(fd), F_GETFL, 0)
    if curFlags >= 0: discard fcntl(cint(fd), F_SETFL, curFlags or O_NONBLOCK)
  var sndbuf: cint = 256 * 1024
  discard setsockopt(fd, SOL_SOCKET, SO_SNDBUF, addr sndbuf, SockLen(sizeof(sndbuf)))
  var sa: Sockaddr_un
  sa.sun_family = TSa_Family(AF_UNIX)
  let n = min(path.len, sa.sun_path.len - 1)
  for i in 0 ..< n: sa.sun_path[i] = path[i]
  sa.sun_path[n] = '\x00'
  let slen = SockLen(sizeof(Sockaddr_un.sun_family) + n + 1)

  # Retry loop: tolerate EAGAIN/EINPROGRESS/ECONNREFUSED while server is
  # in the bind()<->listen() window. 200 attempts * 10ms = 2s ceiling.
  var attempts = 0
  var connected = false
  while attempts < 200:
    let rc = connect(fd, cast[ptr SockAddr](addr sa), slen)
    if rc == 0:
      connected = true
      break
    let e = errno
    if e == EINTR:
      continue
    if e == EAGAIN or e == EINPROGRESS or e == ECONNREFUSED or e == ENOENT:
      sleep(10)
      inc attempts
      continue
    # any other errno: fail loud
    discard posix.close(fd)
    raise newException(OSError, "connect failed: " & path & " errno=" & $e)
  if not connected:
    discard posix.close(fd)
    raise newException(OSError, "connect timeout after 2s: " & path)

  # Back to blocking mode so downstream sendmsg() semantics stay unchanged.
  let cur = fcntl(cint(fd), F_GETFL, 0)
  if cur >= 0:
    discard fcntl(cint(fd), F_SETFL, cur and not O_NONBLOCK)
  return cint(fd)

proc waitForPath(path: string) =
  var tries = 0
  while tries < 600:
    if access(path.cstring, F_OK) == 0: return
    sleep(100)
    inc tries
  raise newException(OSError, "timeout waiting for " & path)

proc sendFd(udsFd: cint, clientFd: cint): bool =
  var dummy: uint8 = 1
  var iov: Iovec_t
  iov.iov_base = addr dummy
  iov.iov_len = 1
  let CTRL_LEN = 64
  var ctrlBuf {.noinit.}: array[64, uint8]
  var msg: Msghdr_t
  msg.msg_name = nil
  msg.msg_namelen = 0
  msg.msg_iov = addr iov
  msg.msg_iovlen = 1
  msg.msg_control = addr ctrlBuf[0]
  msg.msg_controllen = csize_t(CTRL_LEN)
  msg.msg_flags = 0
  let cmsg = cast[ptr CmsghdrPort](addr ctrlBuf[0])
  cmsg.len = csize_t(cmsgLen(sizeof(cint)))
  cmsg.level = SOL_SOCKET_C
  cmsg.typ = SCM_RIGHTS_C
  let dataOff = cmsgAlign(sizeof(CmsghdrPort))
  let dataPtr = cast[ptr cint](addr ctrlBuf[dataOff])
  dataPtr[] = clientFd
  msg.msg_controllen = cmsg.len
  while true:
    let r = sendmsg_c(udsFd, addr msg, MSG_NOSIGNAL_C or MSG_DONTWAIT_C)
    if r > 0: return true
    let e = errno
    if e == EINTR: continue
    return false

const MAX_PREFIX* = 4096

proc sendFdWithBytes(udsFd: cint, clientFd: cint, prefix: ptr uint8, prefixLen: int): bool =
  ## Send clientFd along with a u16-length-prefixed byte buffer (HTTP head) in
  ## a single sendmsg() so the worker recovers fd + bytes in one syscall.
  var lenLE: uint16 = uint16(prefixLen)
  var iov: array[2, Iovec_t]
  iov[0].iov_base = addr lenLE
  iov[0].iov_len = csize_t(sizeof(uint16))
  iov[1].iov_base = prefix
  iov[1].iov_len = csize_t(prefixLen)
  let CTRL_LEN = 64
  var ctrlBuf {.noinit.}: array[64, uint8]
  var msg: Msghdr_t
  msg.msg_name = nil
  msg.msg_namelen = 0
  msg.msg_iov = addr iov[0]
  msg.msg_iovlen = 2
  msg.msg_control = addr ctrlBuf[0]
  msg.msg_controllen = csize_t(CTRL_LEN)
  msg.msg_flags = 0
  let cmsg = cast[ptr CmsghdrPort](addr ctrlBuf[0])
  cmsg.len = csize_t(cmsgLen(sizeof(cint)))
  cmsg.level = SOL_SOCKET_C
  cmsg.typ = SCM_RIGHTS_C
  let dataOff = cmsgAlign(sizeof(CmsghdrPort))
  let dataPtr = cast[ptr cint](addr ctrlBuf[dataOff])
  dataPtr[] = clientFd
  msg.msg_controllen = cmsg.len
  while true:
    let r = sendmsg_c(udsFd, addr msg, MSG_NOSIGNAL_C or MSG_DONTWAIT_C)
    if r > 0: return true
    let e = errno
    if e == EINTR: continue
    return false

proc readPrefix(fd: cint, buf: ptr uint8, cap: int): int =
  ## Drain bytes that are already in the socket buffer (TCP_DEFER_ACCEPT means
  ## the kernel only wakes us after data arrived). Stops on EAGAIN.
  var n = 0
  while n < cap:
    let r = posix.recv(SocketHandle(fd),
      cast[pointer](cast[uint](buf) + uint(n)),
      cap - n, MSG_DONTWAIT_C)
    if r > 0:
      n += int(r)
      continue
    if r == 0: return n
    let e = errno
    if e == EINTR: continue
    break
  return n

proc openListener(port: uint16, backlog: int): cint =
  let fd = socket(AF_INET, SOCK_STREAM or SOCK_NONBLOCK_C or SOCK_CLOEXEC_C, 0)
  if cint(fd) < 0: raise newException(OSError, "socket failed")
  var one: cint = 1
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, addr one, SockLen(sizeof(one)))
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, addr one, SockLen(sizeof(one)))
  discard setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT_C, addr one, SockLen(sizeof(one)))
  var sa: Sockaddr_in
  sa.sin_family = TSa_Family(AF_INET)
  sa.sin_port = posix.htons(port)
  sa.sin_addr.s_addr = 0
  if bindSocket(fd, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) < 0:
    raise newException(OSError, "bind tcp failed")
  if listen(fd, cint(backlog)) < 0:
    raise newException(OSError, "listen tcp failed")
  return cint(fd)

proc main() =
  let portStr = getEnv("LB_PORT", "9999")
  let port = uint16(parseInt(portStr))
  let backlog = parseInt(getEnv("LB_BACKLOG", $DEFAULT_BACKLOG))
  let acceptBatch = parseInt(getEnv("LB_ACCEPT_BATCH", $DEFAULT_ACCEPT_BATCH))
  let sockets = getEnv("API_SOCKETS", "")
  if sockets.len == 0:
    stderr.writeLine "[lb] set API_SOCKETS=/sock/api1.sock,/sock/api2.sock"; stderr.flushFile
    quit(1)

  var backendFds: array[MAX_BACKENDS, cint]
  var nb = 0
  for raw in sockets.split(','):
    let p = raw.strip()
    if p.len == 0: continue
    if nb >= MAX_BACKENDS: break
    stderr.writeLine "[lb] waiting for ", p; stderr.flushFile
    waitForPath(p)
    stderr.writeLine "[lb] connecting to ", p; stderr.flushFile
    backendFds[nb] = connectUds(p)
    stderr.writeLine "[lb] connected to ", p, " fd=", backendFds[nb]; stderr.flushFile
    inc nb
  if nb == 0:
    stderr.writeLine "[lb] no backends"; stderr.flushFile
    quit(1)

  stderr.writeLine "[lb] opening listener port=", port; stderr.flushFile
  let lfd = openListener(port, backlog)
  stderr.writeLine "[lb] listening :", port, " batch=", acceptBatch, " backends=", nb; stderr.flushFile

  var rr = 0
  var pfd: array[1, TPollfd]
  var prefixBuf {.noinit.}: array[MAX_PREFIX, uint8]
  while true:
    var accepted = 0
    var gotOne = false
    while accepted < acceptBatch:
      let cfd = accept4(lfd, nil, nil, SOCK_NONBLOCK_C or SOCK_CLOEXEC_C)
      if cfd < 0: break
      gotOne = true
      var one: cint = 1
      discard setsockopt(SocketHandle(cfd), IPPROTO_TCP, TCP_NODELAY_C, addr one, SockLen(sizeof(one)))
      discard setsockopt(SocketHandle(cfd), IPPROTO_TCP, TCP_QUICKACK_C, addr one, SockLen(sizeof(one)))
      # TCP_DEFER_ACCEPT on the listener means the kernel woke us only once
      # client data was queued, so a non-blocking recv() drains the head of
      # the HTTP request without an extra syscall round trip on the worker.
      let plen = readPrefix(cfd, addr prefixBuf[0], MAX_PREFIX)
      let start = rr
      var attempt = 0
      var sent = false
      while attempt < nb:
        let idx = (start + attempt) mod nb
        if sendFdWithBytes(backendFds[idx], cfd, addr prefixBuf[0], plen):
          rr = (idx + 1) mod nb
          sent = true
          break
        inc attempt
      discard posix.close(cfd)
      if not sent: discard
      inc accepted
    if not gotOne:
      pfd[0].fd = lfd
      pfd[0].events = POLLIN
      pfd[0].revents = 0
      discard poll(addr pfd[0], 1, 60_000)

when isMainModule:
  main()
