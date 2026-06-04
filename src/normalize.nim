
import json_parser, time_iso

const
  DIMS* = 14
  PADDED_DIMS* = 16
  MAX_AMOUNT: float32 = 10_000.0
  MAX_INSTALLMENTS: float32 = 12.0
  AMOUNT_VS_AVG_RATIO: float32 = 10.0
  MAX_MINUTES: float32 = 1440.0
  MAX_KM: float32 = 1000.0
  MAX_TX_COUNT_24H: float32 = 20.0
  MAX_MERCHANT_AVG_AMOUNT: float32 = 10_000.0

template clamp01(x: float32): float32 =
  (if x < 0.0'f32: 0.0'f32 elif x > 1.0'f32: 1.0'f32 else: x)

proc packMcc(s: json_parser.Slice): uint32 {.inline.} =
  if s.n != 4: return 0
  (uint32(s.p[0]) shl 24) or (uint32(s.p[1]) shl 16) or (uint32(s.p[2]) shl 8) or uint32(s.p[3])

template packLit(a, b, c, d: char): uint32 =
  (uint32(a) shl 24) or (uint32(b) shl 16) or (uint32(c) shl 8) or uint32(d)

proc mccRisk(s: json_parser.Slice): float32 {.inline.} =
  if s.n != 4: return 0.5'f32
  let x = packMcc(s)
  case x
  of packLit('5','4','1','1'): 0.15'f32
  of packLit('5','8','1','2'): 0.30'f32
  of packLit('5','9','1','2'): 0.20'f32
  of packLit('5','9','4','4'): 0.45'f32
  of packLit('7','8','0','1'): 0.80'f32
  of packLit('7','8','0','2'): 0.75'f32
  of packLit('7','9','9','5'): 0.85'f32
  of packLit('4','5','1','1'): 0.35'f32
  of packLit('5','3','1','1'): 0.25'f32
  of packLit('5','9','9','9'): 0.50'f32
  else: 0.5'f32

proc vectorize*(p: ptr Payload): array[DIMS, float32] =
  let ts = parse(toOpenArray(p.requested_at.p, 0, p.requested_at.n - 1))
  let cur = epochSeconds(ts)
  let dow = dayOfWeek(ts.year, ts.month, ts.day)

  var known = false
  for i in 0 ..< int(p.known_n):
    let m = p.known_merchants[i]
    if m.n == p.merchant_id.n:
      var same = true
      for j in 0 ..< m.n:
        if m.p[j] != p.merchant_id.p[j]:
          same = false
          break
      if same:
        known = true
        break

  var d5: float32 = -1.0'f32
  var d6: float32 = -1.0'f32
  if p.has_last:
    let lts = parse(toOpenArray(p.last_timestamp.p, 0, p.last_timestamp.n - 1))
    let last = epochSeconds(lts)
    var minsRaw = float32(cur - last) / 60.0'f32
    if minsRaw < 0.0'f32: minsRaw = 0.0'f32
    d5 = clamp01(minsRaw / MAX_MINUTES)
    d6 = clamp01(p.last_km_from_current / MAX_KM)

  result[0]  = clamp01(p.amount / MAX_AMOUNT)
  result[1]  = clamp01(float32(p.installments) / MAX_INSTALLMENTS)
  result[2]  = clamp01((p.amount / p.avg_amount) / AMOUNT_VS_AVG_RATIO)
  result[3]  = float32(ts.hour) / 23.0'f32
  result[4]  = float32(dow) / 6.0'f32
  result[5]  = d5
  result[6]  = d6
  result[7]  = clamp01(p.km_from_home / MAX_KM)
  result[8]  = clamp01(float32(p.tx_count_24h) / MAX_TX_COUNT_24H)
  result[9]  = (if p.is_online: 1.0'f32 else: 0.0'f32)
  result[10] = (if p.card_present: 1.0'f32 else: 0.0'f32)
  result[11] = (if known: 0.0'f32 else: 1.0'f32)
  result[12] = mccRisk(p.mcc)
  result[13] = clamp01(p.merchant_avg_amount / MAX_MERCHANT_AVG_AMOUNT)
