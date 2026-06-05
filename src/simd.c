
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LANES 8
#define PADDED_DIMS 16
#define PAIRS 8
#define BLOCK_WORDS (PADDED_DIMS * LANES)
#define BLOCK_BYTES (BLOCK_WORDS * 2)

#if defined(__AVX2__)
#include <immintrin.h>

static inline int64_t hsum_madd_i64(__m256i d) {
    __m256i madd = _mm256_madd_epi16(d, d);
    __m256i lo = _mm256_cvtepi32_epi64(_mm256_castsi256_si128(madd));
    __m256i hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(madd, 1));
    __m256i sum = _mm256_add_epi64(lo, hi);
    __m128i sum_lo = _mm256_castsi256_si128(sum);
    __m128i sum_hi = _mm256_extracti128_si256(sum, 1);
    __m128i pair = _mm_add_epi64(sum_lo, sum_hi);
    __m128i pair_hi = _mm_unpackhi_epi64(pair, pair);
    return _mm_cvtsi128_si64(_mm_add_epi64(pair, pair_hi));
}

void blk_dist_c(const int16_t* vectors, size_t block_idx, const int16_t* q, int64_t* out) {
    const int16_t* base = vectors + block_idx * BLOCK_WORDS;
    /* Prefetch the next block so the hot scan loop in Nim has its
       cache lines primed. Block stride is 256 bytes = 4 cache lines. */
    const char* next = (const char*)(base + BLOCK_WORDS);
    _mm_prefetch(next, _MM_HINT_T0);
    _mm_prefetch(next + 64, _MM_HINT_T0);
    _mm_prefetch(next + 128, _MM_HINT_T0);
    _mm_prefetch(next + 192, _MM_HINT_T0);

    __m256i acc_lo = _mm256_setzero_si256(); /* 4x i64 */
    __m256i acc_hi = _mm256_setzero_si256();

    for (int p = 0; p < PAIRS; ++p) {
        int32_t pair = ((int32_t)(uint16_t)q[2*p]) | (((int32_t)q[2*p+1]) << 16);
        __m256i q_pair = _mm256_set1_epi32(pair);
        __m256i block_v = _mm256_loadu_si256((const __m256i*)(base + p * LANES * 2));
        __m256i diff = _mm256_sub_epi16(q_pair, block_v);
        __m256i mad = _mm256_madd_epi16(diff, diff);
        __m256i lo = _mm256_cvtepi32_epi64(_mm256_castsi256_si128(mad));
        __m256i hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(mad, 1));
        acc_lo = _mm256_add_epi64(acc_lo, lo);
        acc_hi = _mm256_add_epi64(acc_hi, hi);
    }
    _mm256_storeu_si256((__m256i*)(out + 0), acc_lo);
    _mm256_storeu_si256((__m256i*)(out + 4), acc_hi);
}

int blk_dist_prune_c(const int16_t* vectors, size_t block_idx, const int16_t* q, int64_t threshold, int64_t* out) {
    const int16_t* base = vectors + block_idx * BLOCK_WORDS;
    /* Prefetch ahead-1 block (next 256B = 4 lines). Matches bmtec/top-5 strategy
       of priming the next cluster block while we crunch the current one. */
    const char* next = (const char*)(base + BLOCK_WORDS);
    _mm_prefetch(next, _MM_HINT_T0);
    _mm_prefetch(next + 64, _MM_HINT_T0);
    _mm_prefetch(next + 128, _MM_HINT_T0);
    _mm_prefetch(next + 192, _MM_HINT_T0);

    __m256i acc_lo = _mm256_setzero_si256();
    __m256i acc_hi = _mm256_setzero_si256();
    __m256i thr = _mm256_set1_epi64x(threshold);

    for (int p = 0; p < PAIRS; ++p) {
        int32_t pair = ((int32_t)(uint16_t)q[2*p]) | (((int32_t)q[2*p+1]) << 16);
        __m256i q_pair = _mm256_set1_epi32(pair);
        __m256i block_v = _mm256_loadu_si256((const __m256i*)(base + p * LANES * 2));
        __m256i diff = _mm256_sub_epi16(q_pair, block_v);
        __m256i mad = _mm256_madd_epi16(diff, diff);
        __m256i lo = _mm256_cvtepi32_epi64(_mm256_castsi256_si128(mad));
        __m256i hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(mad, 1));
        acc_lo = _mm256_add_epi64(acc_lo, lo);
        acc_hi = _mm256_add_epi64(acc_hi, hi);
        if (p == 2 || p == 4) {
            __m256i gt_lo = _mm256_cmpgt_epi64(thr, acc_lo); /* 1s if thr > acc, ie acc < thr */
            __m256i gt_hi = _mm256_cmpgt_epi64(thr, acc_hi);
            /* if NEITHER lane is below threshold, prune */
            if (_mm256_testz_si256(gt_lo, gt_lo) && _mm256_testz_si256(gt_hi, gt_hi)) {
                return 0;
            }
        }
    }
    _mm256_storeu_si256((__m256i*)(out + 0), acc_lo);
    _mm256_storeu_si256((__m256i*)(out + 4), acc_hi);
    return 1;
}

/* AVX2 branchless lower-bound: PADDED_DIMS=16 fits exactly in one __m256i of int16.
   Replaces the previous 16-iteration scalar loop. Mirrors bmtec's
   lower_bound_block_i16 (distance.c:51-65). */
int64_t bbox_lb_c(const int16_t* q, const int16_t* mn, const int16_t* mx) {
    __m256i qv = _mm256_loadu_si256((const __m256i*)q);
    __m256i lo = _mm256_loadu_si256((const __m256i*)mn);
    __m256i hi = _mm256_loadu_si256((const __m256i*)mx);

    __m256i below = _mm256_cmpgt_epi16(lo, qv);
    __m256i above = _mm256_cmpgt_epi16(qv, hi);
    __m256i below_diff = _mm256_sub_epi16(lo, qv);
    __m256i above_diff = _mm256_sub_epi16(qv, hi);
    __m256i diff = _mm256_or_si256(
        _mm256_and_si256(below, below_diff),
        _mm256_and_si256(above, above_diff)
    );
    return hsum_madd_i64(diff);
}

/* Prefetch one block (256 B = 4 cache lines) at the given index.
   Exposed to Nim so scanCluster can prime ahead-N blocks. */
void blk_prefetch_c(const int16_t* vectors, size_t block_idx) {
    const char* p = (const char*)(vectors + block_idx * BLOCK_WORDS);
    _mm_prefetch(p, _MM_HINT_T0);
    _mm_prefetch(p + 64, _MM_HINT_T0);
    _mm_prefetch(p + 128, _MM_HINT_T0);
    _mm_prefetch(p + 192, _MM_HINT_T0);
}

#else

void blk_dist_c(const int16_t* vectors, size_t block_idx, const int16_t* q, int64_t* out) {
    const int16_t* base = vectors + block_idx * BLOCK_WORDS;
    int64_t acc[LANES];
    for (int l = 0; l < LANES; ++l) acc[l] = 0;
    for (int p = 0; p < PAIRS; ++p) {
        const int16_t* pair_base = base + p * LANES * 2;
        int16_t qa = q[2*p];
        int16_t qb = q[2*p + 1];
        for (int l = 0; l < LANES; ++l) {
            int32_t da = (int32_t)qa - (int32_t)pair_base[l*2];
            int32_t db = (int32_t)qb - (int32_t)pair_base[l*2 + 1];
            acc[l] += (int64_t)(da*da + db*db);
        }
    }
    for (int l = 0; l < LANES; ++l) out[l] = acc[l];
}

int blk_dist_prune_c(const int16_t* vectors, size_t block_idx, const int16_t* q, int64_t threshold, int64_t* out) {
    const int16_t* base = vectors + block_idx * BLOCK_WORDS;
    int64_t acc[LANES];
    for (int l = 0; l < LANES; ++l) acc[l] = 0;
    for (int p = 0; p < PAIRS; ++p) {
        const int16_t* pair_base = base + p * LANES * 2;
        int16_t qa = q[2*p];
        int16_t qb = q[2*p + 1];
        for (int l = 0; l < LANES; ++l) {
            int32_t da = (int32_t)qa - (int32_t)pair_base[l*2];
            int32_t db = (int32_t)qb - (int32_t)pair_base[l*2 + 1];
            acc[l] += (int64_t)(da*da + db*db);
        }
        if (p == 2 || p == 4) {
            int all_exceed = 1;
            for (int l = 0; l < LANES; ++l) if (acc[l] < threshold) { all_exceed = 0; break; }
            if (all_exceed) return 0;
        }
    }
    for (int l = 0; l < LANES; ++l) out[l] = acc[l];
    return 1;
}

int64_t bbox_lb_c(const int16_t* q, const int16_t* mn, const int16_t* mx) {
    int64_t sum = 0;
    for (int j = 0; j < PADDED_DIMS; ++j) {
        int32_t g = 0;
        int32_t below = (int32_t)mn[j] - (int32_t)q[j];
        int32_t above = (int32_t)q[j] - (int32_t)mx[j];
        if (below > g) g = below;
        if (above > g) g = above;
        sum += (int64_t)g * (int64_t)g;
    }
    return sum;
}

void blk_prefetch_c(const int16_t* vectors, size_t block_idx) {
    (void)vectors;
    (void)block_idx;
}

#endif
