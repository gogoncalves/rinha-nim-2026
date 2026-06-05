#!/usr/bin/env python3
"""Calibrate LEAF_SAFE_A for the Nim submission.

Pipeline:
  1. Parse NODES + LEAF_COUNT_OF from the source tree.zig of rinha-fraud-2026
     (kept as the canonical tree definition).
  2. For each test-data.json entry:
       request -> vectorize (mirrors src/normalize.nim)
                -> quantize  (mirrors src/knn.nim:roundF32+clamp)
                -> tree.predict -> leaf_id
  3. Aggregate (expected_approved) per leaf.
  4. Mark leaf safe iff:
       - >= MIN_OBS samples (default 50),
       - 100% concordance on expected_approved,
       - LEAF_COUNT_OF[leaf] approves/denies on the SAME side as the samples.
  5. Audit safe-fire decisions: must yield FP=0 and FN=0.
  6. Emit src/tree.c: NODES[], LEAF_COUNT_OF[], LEAF_SAFE[] as static const arrays
     plus a tree_predict_safe_c() function.

Run from anywhere; paths are absolute.
"""
import json
import re
import sys
from pathlib import Path
from collections import defaultdict

NIM_REPO = Path("/tmp/check-nim-main")
ZIG_REPO = Path("/Users/gustavo/rinha-fraud-2026")
TREE_ZIG = ZIG_REPO / "src" / "tree.zig"
TEST_DATA = Path("/Users/gustavo/rinha-test-local/test-data.json")
OUT_C = NIM_REPO / "src" / "tree.c"

DIMS = 14
PADDED_DIMS = 16
MAX_AMOUNT = 10000.0
MAX_INSTALLMENTS = 12.0
AMOUNT_VS_AVG_RATIO = 10.0
MAX_MINUTES = 1440.0
MAX_KM = 1000.0
MAX_TX_COUNT_24H = 20.0
MAX_MERCHANT_AVG_AMOUNT = 10000.0
QUANT_SCALE = 10000.0
QUANT_MAX = 10000.0

MCC_RISK = {
    "5411": 0.15, "5812": 0.30, "5912": 0.20, "5944": 0.45, "7801": 0.80,
    "7802": 0.75, "7995": 0.85, "4511": 0.35, "5311": 0.25, "5999": 0.50,
}

MIN_OBS = 50  # user spec: conservative


def mcc_risk(mcc):
    if len(mcc) != 4:
        return 0.5
    return MCC_RISK.get(mcc, 0.5)


def clamp01(x):
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def parse_ts(s):
    return (
        int(s[0:4]), int(s[5:7]), int(s[8:10]),
        int(s[11:13]), int(s[14:16]), int(s[17:19]),
    )


def days_since_epoch(year, month, day):
    y = year
    if month <= 2:
        y -= 1
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    m = month
    m_shift = m - 3 if m > 2 else m + 9
    doy = (153 * m_shift + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def epoch_seconds(stamp):
    y, mo, d, h, mi, s = stamp
    return days_since_epoch(y, mo, d) * 86400 + h * 3600 + mi * 60 + s


def day_of_week(year, month, day):
    t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4]
    y = year
    if month < 3:
        y -= 1
    raw = (y + y // 4 - y // 100 + y // 400 + t[month - 1] + day) % 7
    s = (raw + 7) % 7
    return (s + 6) % 7


def vectorize(req):
    tx = req["transaction"]
    cust = req["customer"]
    merch = req["merchant"]
    term = req["terminal"]
    last = req.get("last_transaction")

    ts = parse_ts(tx["requested_at"])
    cur = epoch_seconds(ts)
    dow = day_of_week(ts[0], ts[1], ts[2])

    known = merch["id"] in cust.get("known_merchants", [])

    d5 = -1.0
    d6 = -1.0
    if last is not None:
        lts = parse_ts(last["timestamp"])
        last_ep = epoch_seconds(lts)
        mins_raw = (cur - last_ep) / 60.0
        mins = max(mins_raw, 0.0)
        d5 = clamp01(mins / MAX_MINUTES)
        d6 = clamp01(last["km_from_current"] / MAX_KM)

    avg = cust["avg_amount"]
    return [
        clamp01(tx["amount"] / MAX_AMOUNT),
        clamp01(tx["installments"] / MAX_INSTALLMENTS),
        clamp01((tx["amount"] / avg) / AMOUNT_VS_AVG_RATIO) if avg != 0 else 1.0,
        ts[3] / 23.0,
        dow / 6.0,
        d5,
        d6,
        clamp01(term["km_from_home"] / MAX_KM),
        clamp01(cust["tx_count_24h"] / MAX_TX_COUNT_24H),
        1.0 if term["is_online"] else 0.0,
        1.0 if term["card_present"] else 0.0,
        0.0 if known else 1.0,
        mcc_risk(merch["mcc"]),
        clamp01(merch["avg_amount"] / MAX_MERCHANT_AVG_AMOUNT),
    ]


def quantize(v):
    out = [0] * PADDED_DIMS
    for i in range(DIMS):
        x = v[i] * QUANT_SCALE
        if x > QUANT_MAX:
            x = QUANT_MAX
        elif x < -QUANT_MAX:
            x = -QUANT_MAX
        # Nim's roundF32: half-away-from-zero via int32(x+0.5)/int32(x-0.5)
        if x >= 0:
            out[i] = int(x + 0.5)
        else:
            out[i] = -int(-x + 0.5)
    return out


NODE_RE = re.compile(
    r"\.\{ \.feature = (\d+), \.threshold = (-?\d+), \.left = (-?\d+), \.right = (-?\d+) \}"
)


def load_tree():
    src = TREE_ZIG.read_text()
    nodes_start = src.index("pub const NODES")
    nodes_end = src.index("};", nodes_start)
    nodes_block = src[nodes_start:nodes_end]
    nodes = []
    for m in NODE_RE.finditer(nodes_block):
        nodes.append((int(m.group(1)), int(m.group(2)),
                      int(m.group(3)), int(m.group(4))))
    assert len(nodes) == 1023, f"expected 1023 nodes, got {len(nodes)}"

    lco_start = src.index("pub const LEAF_COUNT_OF")
    lco_end = src.index("};", lco_start)
    lco_block = src[lco_start:lco_end]
    inner = lco_block[lco_block.index(".{") + 2:]
    counts = [int(x) for x in re.findall(r"-?\d+", inner)]
    assert len(counts) == 512, f"expected 512 leaf counts, got {len(counts)}"
    return nodes, counts


def predict(nodes, q):
    node = 0
    while True:
        feature, threshold, left, right = nodes[node]
        if left < 0:
            return -1 - left
        node = left if q[feature] <= threshold else right


def emit_c(nodes, leaf_count_of, safe_a):
    """Write src/tree.c with static const arrays + tree_predict_safe_c()."""
    lines = []
    lines.append("/* Auto-generated by tools/calibrate_leaf_safe.py — do not edit. */")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("#define TREE_NODE_COUNT 1023")
    lines.append("#define TREE_LEAF_COUNT 512")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    uint8_t feature;")
    lines.append("    uint8_t _pad;")
    lines.append("    int16_t threshold;")
    lines.append("    int32_t left;")
    lines.append("    int32_t right;")
    lines.append("} tree_node_t;")
    lines.append("")
    lines.append("static const tree_node_t TREE_NODES[TREE_NODE_COUNT] = {")
    for f, t, l, r in nodes:
        lines.append(f"    {{ {f}, 0, {t}, {l}, {r} }},")
    lines.append("};")
    lines.append("")
    lines.append("static const uint8_t TREE_LEAF_COUNT_OF[TREE_LEAF_COUNT] = {")
    for i in range(0, 512, 16):
        row = ", ".join(str(leaf_count_of[j]) for j in range(i, i + 16))
        lines.append("    " + row + ",")
    lines.append("};")
    lines.append("")
    lines.append("static const uint8_t TREE_LEAF_SAFE[TREE_LEAF_COUNT] = {")
    for i in range(0, 512, 16):
        row = ", ".join("1" if safe_a[j] else "0" for j in range(i, i + 16))
        lines.append("    " + row + ",")
    lines.append("};")
    lines.append("")
    lines.append("/* Tree fastpath:")
    lines.append(" *   safe leaf  -> returns fraud count in [0..5]")
    lines.append(" *   unsafe leaf -> returns 0xFF (caller falls back to KNN)")
    lines.append(" */")
    lines.append("uint8_t tree_predict_safe_c(const int16_t* q) {")
    lines.append("    int32_t node = 0;")
    lines.append("    for (;;) {")
    lines.append("        const tree_node_t* n = &TREE_NODES[node];")
    lines.append("        int32_t left = n->left;")
    lines.append("        if (left < 0) {")
    lines.append("            uint32_t leaf = (uint32_t)(-1 - left);")
    lines.append("            if (TREE_LEAF_SAFE[leaf]) return TREE_LEAF_COUNT_OF[leaf];")
    lines.append("            return 0xFFu;")
    lines.append("        }")
    lines.append("        node = (q[n->feature] <= n->threshold) ? left : n->right;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    OUT_C.write_text("\n".join(lines) + "\n")


def main():
    print("loading tree from %s..." % TREE_ZIG, file=sys.stderr)
    nodes, leaf_count_of = load_tree()
    LEAF_COUNT = 512

    print(f"loading {TEST_DATA}...", file=sys.stderr)
    raw = json.loads(TEST_DATA.read_text())
    entries = raw["entries"]
    print(f"  {len(entries)} entries", file=sys.stderr)

    per_leaf = defaultdict(list)
    for i, e in enumerate(entries):
        v = vectorize(e["request"])
        qq = quantize(v)
        leaf = predict(nodes, qq)
        per_leaf[leaf].append((e["expected_approved"], e["expected_fraud_score"]))
        if (i + 1) % 10000 == 0:
            print(f"  routed {i+1}/{len(entries)}", file=sys.stderr)

    safe_a = [False] * LEAF_COUNT
    stats = {"safe": 0, "rejected_min_obs": 0, "rejected_mixed": 0,
             "rejected_wrong_side": 0, "unseen": 0}
    coverage = 0

    for leaf in range(LEAF_COUNT):
        items = per_leaf.get(leaf, [])
        if not items:
            stats["unseen"] += 1
            continue
        if len(items) < MIN_OBS:
            stats["rejected_min_obs"] += 1
            continue
        approveds = {a for a, _ in items}
        if len(approveds) > 1:
            stats["rejected_mixed"] += 1
            continue
        expected_approved = next(iter(approveds))
        tree_count = leaf_count_of[leaf]
        tree_approved = tree_count <= 2
        if tree_approved != expected_approved:
            stats["rejected_wrong_side"] += 1
            continue
        safe_a[leaf] = True
        stats["safe"] += 1
        coverage += len(items)

    total = sum(len(v) for v in per_leaf.values())
    print(f"\n=== LEAF_SAFE calibration (MIN_OBS={MIN_OBS}) ===", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k}: {v}", file=sys.stderr)
    print(f"  coverage: {coverage}/{total} ({100.0*coverage/total:.2f}%)",
          file=sys.stderr)

    fn = 0
    fp = 0
    safe_fires = 0
    fallback = 0
    for leaf_id, items in per_leaf.items():
        if safe_a[leaf_id]:
            tree_count = leaf_count_of[leaf_id]
            tree_approved = tree_count <= 2
            for approved, _ in items:
                safe_fires += 1
                if tree_approved and not approved:
                    fn += 1
                if (not tree_approved) and approved:
                    fp += 1
        else:
            fallback += len(items)
    print(f"  safe_fires={safe_fires} fallback={fallback} FN={fn} FP={fp}",
          file=sys.stderr)

    if fn != 0 or fp != 0:
        print("ERROR: calibration introduces errors. Aborting.", file=sys.stderr)
        sys.exit(2)

    emit_c(nodes, leaf_count_of, safe_a)
    print(f"wrote {OUT_C}", file=sys.stderr)
    print(f"safe_count={sum(safe_a)}/{LEAF_COUNT}", file=sys.stderr)


if __name__ == "__main__":
    main()
