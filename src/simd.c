
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

void blk_dist_c(const int16_t* vectors, size_t block_idx, const int16_t* q, int64_t* out) {
    const int16_t* base = vectors + block_idx * BLOCK_WORDS;
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

#endif
