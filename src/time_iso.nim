
type
  Stamp* = object
    year*: int32
    month*: uint32
    day*: uint32
    hour*: uint32
    minute*: uint32
    second*: uint32

template d(c: char): uint32 = uint32(ord(c) - ord('0'))
template di(c: char): int32 = int32(ord(c) - ord('0'))

proc parse*(s: openArray[char]): Stamp {.inline.} =
  result.year   = di(s[0]) * 1000 + di(s[1]) * 100 + di(s[2]) * 10 + di(s[3])
  result.month  = d(s[5]) * 10 + d(s[6])
  result.day    = d(s[8]) * 10 + d(s[9])
  result.hour   = d(s[11]) * 10 + d(s[12])
  result.minute = d(s[14]) * 10 + d(s[15])
  result.second = d(s[17]) * 10 + d(s[18])

proc dayOfWeek*(year: int32, month: uint32, day: uint32): uint32 {.inline.} =
  const t = [int32 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4]
  var y = year
  if month < 3'u32: dec y
  let raw = (y + y div 4 - y div 100 + y div 400 + t[int(month) - 1] + int32(day)) mod 7
  let s = uint32(((raw mod 7) + 7) mod 7)
  result = (s + 6) mod 7

proc daysSinceEpoch*(year: int32, month: uint32, day: uint32): int64 {.inline.} =
  var y = int64(year)
  if month <= 2'u32: dec y
  let era = (if y >= 0: y else: y - 399) div 400
  let yoe = y - era * 400
  let m = int64(month)
  let mShift = if m > 2: m - 3 else: m + 9
  let doy = (153 * mShift + 2) div 5 + int64(day) - 1
  let doe = yoe * 365 + yoe div 4 - yoe div 100 + doy
  result = era * 146097 + doe - 719468

proc epochSeconds*(s: Stamp): int64 {.inline.} =
  daysSinceEpoch(s.year, s.month, s.day) * 86400 +
    int64(s.hour) * 3600 +
    int64(s.minute) * 60 +
    int64(s.second)
