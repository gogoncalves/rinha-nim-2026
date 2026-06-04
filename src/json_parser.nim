
const MAX_KNOWN* = 16

type
  Slice* = object
    p*: ptr UncheckedArray[char]
    n*: int

  Payload* = object
    amount*: float32
    installments*: uint32
    requested_at*: Slice
    avg_amount*: float32
    tx_count_24h*: uint32
    known_merchants*: array[MAX_KNOWN, Slice]
    known_n*: uint32
    merchant_id*: Slice
    mcc*: Slice
    merchant_avg_amount*: float32
    is_online*: bool
    card_present*: bool
    km_from_home*: float32
    has_last*: bool
    last_timestamp*: Slice
    last_km_from_current*: float32

  ParseError* = object of ValueError

template raiseBad() = raise newException(ParseError, "bad json")

proc eqStr(s: Slice, lit: string): bool {.inline.} =
  if s.n != lit.len: return false
  for i in 0 ..< lit.len:
    if s.p[i] != lit[i]: return false
  true

proc eqSlice(a, b: Slice): bool {.inline.} =
  if a.n != b.n: return false
  for i in 0 ..< a.n:
    if a.p[i] != b.p[i]: return false
  true

proc skipWs(buf: ptr UncheckedArray[char], i: var int, n: int) {.inline.} =
  while i < n:
    let c = buf[i]
    if c != ' ' and c != '\t' and c != '\r' and c != '\n': break
    inc i

proc peek(buf: ptr UncheckedArray[char], i: int, n: int): int {.inline.} =
  if i < n: int(buf[i]) else: -1

proc expect(buf: ptr UncheckedArray[char], i: var int, n: int, c: char) {.inline.} =
  skipWs(buf, i, n)
  if i >= n or buf[i] != c: raiseBad()
  inc i

proc readKey(buf: ptr UncheckedArray[char], i: var int, n: int): Slice =
  skipWs(buf, i, n)
  if i >= n or buf[i] != '"': raiseBad()
  inc i
  let start = i
  while i < n and buf[i] != '"': inc i
  if i >= n: raiseBad()
  result = Slice(p: cast[ptr UncheckedArray[char]](addr buf[start]), n: i - start)
  inc i

proc readStr(buf: ptr UncheckedArray[char], i: var int, n: int): Slice =
  skipWs(buf, i, n)
  if i >= n or buf[i] != '"': raiseBad()
  inc i
  let start = i
  while i < n and buf[i] != '"': inc i
  if i >= n: raiseBad()
  result = Slice(p: cast[ptr UncheckedArray[char]](addr buf[start]), n: i - start)
  inc i

proc readBool(buf: ptr UncheckedArray[char], i: var int, n: int): bool =
  skipWs(buf, i, n)
  if i + 4 <= n and buf[i] == 't' and buf[i+1] == 'r' and buf[i+2] == 'u' and buf[i+3] == 'e':
    i += 4
    return true
  if i + 5 <= n and buf[i] == 'f' and buf[i+1] == 'a' and buf[i+2] == 'l' and buf[i+3] == 's' and buf[i+4] == 'e':
    i += 5
    return false
  raiseBad()

proc readU32(buf: ptr UncheckedArray[char], i: var int, n: int): uint32 =
  skipWs(buf, i, n)
  var v: uint32 = 0
  var saw = false
  while i < n:
    let c = buf[i]
    if c < '0' or c > '9': break
    v = v * 10'u32 + uint32(ord(c) - ord('0'))
    inc i
    saw = true
  if not saw: raiseBad()
  v

proc parseF32(p: ptr UncheckedArray[char], n: int): float32 =
  var i = 0
  var sign: float64 = 1.0
  if i < n and p[i] == '-': sign = -1.0; inc i
  elif i < n and p[i] == '+': inc i
  var num: float64 = 0.0
  while i < n and p[i] >= '0' and p[i] <= '9':
    num = num * 10.0 + float64(ord(p[i]) - ord('0'))
    inc i
  if i < n and p[i] == '.':
    inc i
    var frac: float64 = 0.0
    var dvr: float64 = 1.0
    while i < n and p[i] >= '0' and p[i] <= '9':
      frac = frac * 10.0 + float64(ord(p[i]) - ord('0'))
      dvr *= 10.0
      inc i
    num += frac / dvr
  if i < n and (p[i] == 'e' or p[i] == 'E'):
    inc i
    var esign = 1
    if i < n and p[i] == '-': esign = -1; inc i
    elif i < n and p[i] == '+': inc i
    var e = 0
    while i < n and p[i] >= '0' and p[i] <= '9':
      e = e * 10 + (ord(p[i]) - ord('0'))
      inc i
    var m: float64 = 1.0
    while e > 0:
      m *= 10.0
      dec e
    if esign < 0: num /= m else: num *= m
  float32(sign * num)

proc readF32Buf(buf: ptr UncheckedArray[char], i: var int, n: int): float32 =
  skipWs(buf, i, n)
  let start = i
  if i < n and (buf[i] == '-' or buf[i] == '+'): inc i
  while i < n:
    let c = buf[i]
    if not ((c >= '0' and c <= '9') or c == '.' or c == 'e' or c == 'E' or c == '+' or c == '-'):
      break
    inc i
  if i == start: raiseBad()
  parseF32(cast[ptr UncheckedArray[char]](addr buf[start]), i - start)

proc skipVal(buf: ptr UncheckedArray[char], i: var int, n: int) =
  skipWs(buf, i, n)
  if i >= n: return
  let c = buf[i]
  if c == '"':
    inc i
    while i < n and buf[i] != '"': inc i
    if i < n: inc i
    return
  if c == '{' or c == '[':
    let closer = if c == '{': '}' else: ']'
    var depth = 1
    inc i
    while i < n and depth > 0:
      if buf[i] == c: inc depth
      elif buf[i] == closer: dec depth
      inc i
    return
  while i < n:
    let cc = buf[i]
    if cc == ',' or cc == '}' or cc == ']': return
    inc i

proc readTx(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  expect(buf, i, n, '{')
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord('}'): inc i; return
    let k = readKey(buf, i, n)
    expect(buf, i, n, ':')
    skipWs(buf, i, n)
    if eqStr(k, "amount"): p.amount = readF32Buf(buf, i, n)
    elif eqStr(k, "installments"): p.installments = readU32(buf, i, n)
    elif eqStr(k, "requested_at"): p.requested_at = readStr(buf, i, n)
    else: skipVal(buf, i, n)
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc readKnown(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  expect(buf, i, n, '[')
  p.known_n = 0
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(']'): inc i; return
    let s = readStr(buf, i, n)
    if p.known_n < uint32(MAX_KNOWN):
      p.known_merchants[int(p.known_n)] = s
      inc p.known_n
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc readCust(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  expect(buf, i, n, '{')
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord('}'): inc i; return
    let k = readKey(buf, i, n)
    expect(buf, i, n, ':')
    skipWs(buf, i, n)
    if eqStr(k, "avg_amount"): p.avg_amount = readF32Buf(buf, i, n)
    elif eqStr(k, "tx_count_24h"): p.tx_count_24h = readU32(buf, i, n)
    elif eqStr(k, "known_merchants"): readKnown(buf, i, n, p)
    else: skipVal(buf, i, n)
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc readMer(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  expect(buf, i, n, '{')
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord('}'): inc i; return
    let k = readKey(buf, i, n)
    expect(buf, i, n, ':')
    skipWs(buf, i, n)
    if eqStr(k, "id"): p.merchant_id = readStr(buf, i, n)
    elif eqStr(k, "mcc"): p.mcc = readStr(buf, i, n)
    elif eqStr(k, "avg_amount"): p.merchant_avg_amount = readF32Buf(buf, i, n)
    else: skipVal(buf, i, n)
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc readTerm(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  expect(buf, i, n, '{')
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord('}'): inc i; return
    let k = readKey(buf, i, n)
    expect(buf, i, n, ':')
    skipWs(buf, i, n)
    if eqStr(k, "is_online"): p.is_online = readBool(buf, i, n)
    elif eqStr(k, "card_present"): p.card_present = readBool(buf, i, n)
    elif eqStr(k, "km_from_home"): p.km_from_home = readF32Buf(buf, i, n)
    else: skipVal(buf, i, n)
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc readLast(buf: ptr UncheckedArray[char], i: var int, n: int, p: var Payload) =
  skipWs(buf, i, n)
  if i + 4 <= n and buf[i] == 'n' and buf[i+1] == 'u' and buf[i+2] == 'l' and buf[i+3] == 'l':
    i += 4
    p.has_last = false
    return
  expect(buf, i, n, '{')
  p.has_last = true
  while true:
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord('}'): inc i; return
    let k = readKey(buf, i, n)
    expect(buf, i, n, ':')
    skipWs(buf, i, n)
    if eqStr(k, "timestamp"): p.last_timestamp = readStr(buf, i, n)
    elif eqStr(k, "km_from_current"): p.last_km_from_current = readF32Buf(buf, i, n)
    else: skipVal(buf, i, n)
    skipWs(buf, i, n)
    if peek(buf, i, n) == ord(','): inc i

proc parse*(body: ptr UncheckedArray[char], n: int): Payload =
  var i = 0
  expect(body, i, n, '{')
  while true:
    skipWs(body, i, n)
    if peek(body, i, n) == ord('}'): inc i; break
    let k = readKey(body, i, n)
    expect(body, i, n, ':')
    skipWs(body, i, n)
    if eqStr(k, "transaction"): readTx(body, i, n, result)
    elif eqStr(k, "customer"): readCust(body, i, n, result)
    elif eqStr(k, "merchant"): readMer(body, i, n, result)
    elif eqStr(k, "terminal"): readTerm(body, i, n, result)
    elif eqStr(k, "last_transaction"): readLast(body, i, n, result)
    else: skipVal(body, i, n)
    skipWs(body, i, n)
    if peek(body, i, n) == ord(','): inc i
