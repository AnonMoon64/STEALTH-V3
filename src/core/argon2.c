#include "argon2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ARGON2_BLOCK_QWORDS 128
#define ARGON2_BLOCK_SIZE (ARGON2_BLOCK_QWORDS * sizeof(uint64_t))
#define ARGON2_SYNC_POINTS 4
#define ARGON2_VERSION 0x13
#define ARGON2_TYPE_ID 2

// ------- Blake2b (minimal) -------
#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
} blake2b_state;

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

static uint64_t rotr64(uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); }

static void blake2b_init(blake2b_state *S, size_t outlen) {
    memset(S, 0, sizeof(*S));
    memcpy(S->h, blake2b_iv, sizeof(S->h));
    S->h[0] ^= 0x01010000 ^ (uint64_t)outlen;
    S->outlen = outlen;
}

static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES], int last) {
    uint64_t m[16];
    uint64_t v[16];
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint64_t)block[i * 8 + 0]) | ((uint64_t)block[i * 8 + 1] << 8) |
               ((uint64_t)block[i * 8 + 2] << 16) | ((uint64_t)block[i * 8 + 3] << 24) |
               ((uint64_t)block[i * 8 + 4] << 32) | ((uint64_t)block[i * 8 + 5] << 40) |
               ((uint64_t)block[i * 8 + 6] << 48) | ((uint64_t)block[i * 8 + 7] << 56);
    }
    memcpy(v, S->h, sizeof(S->h));
    v[8] = blake2b_iv[0]; v[9] = blake2b_iv[1]; v[10] = blake2b_iv[2]; v[11] = blake2b_iv[3];
    v[12] = S->t[0] ^ blake2b_iv[4]; v[13] = S->t[1] ^ blake2b_iv[5];
    v[14] = S->f[0] ^ blake2b_iv[6]; v[15] = S->f[1] ^ blake2b_iv[7];
#define G(a,b,c,d,x,y) \
    do { \
        a = a + b + x; d = rotr64(d ^ a, 32); \
        c = c + d; b = rotr64(b ^ c, 24); \
        a = a + b + y; d = rotr64(d ^ a, 16); \
        c = c + d; b = rotr64(b ^ c, 63); \
    } while (0)
#define ROUND(r) \
    G(v[0], v[4], v[8], v[12], m[blake2b_sigma[r][0]], m[blake2b_sigma[r][1]]); \
    G(v[1], v[5], v[9], v[13], m[blake2b_sigma[r][2]], m[blake2b_sigma[r][3]]); \
    G(v[2], v[6], v[10], v[14], m[blake2b_sigma[r][4]], m[blake2b_sigma[r][5]]); \
    G(v[3], v[7], v[11], v[15], m[blake2b_sigma[r][6]], m[blake2b_sigma[r][7]]); \
    G(v[0], v[5], v[10], v[15], m[blake2b_sigma[r][8]], m[blake2b_sigma[r][9]]); \
    G(v[1], v[6], v[11], v[12], m[blake2b_sigma[r][10]], m[blake2b_sigma[r][11]]); \
    G(v[2], v[7], v[8], v[13], m[blake2b_sigma[r][12]], m[blake2b_sigma[r][13]]); \
    G(v[3], v[4], v[9], v[14], m[blake2b_sigma[r][14]], m[blake2b_sigma[r][15]]);
    for (int i = 0; i < 12; i++) { ROUND(i); }
#undef G
#undef ROUND
    for (int i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
    (void)last;
}

static void blake2b_update(blake2b_state *S, const uint8_t *in, size_t inlen) {
    size_t i = 0;
    while (i < inlen) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        size_t take = (inlen - i) < fill ? (inlen - i) : fill;
        memcpy(S->buf + left, in + i, take);
        S->buflen += take;
        i += take;
        if (S->buflen == BLAKE2B_BLOCKBYTES) {
            S->t[0] += BLAKE2B_BLOCKBYTES;
            if (S->t[0] < BLAKE2B_BLOCKBYTES) S->t[1]++;
            blake2b_compress(S, S->buf, 0);
            S->buflen = 0;
        }
    }
}

static void blake2b_final(blake2b_state *S, uint8_t *out, size_t outlen) {
    S->t[0] += (uint32_t)S->buflen;
    if (S->t[0] < S->buflen) S->t[1]++;
    S->f[0] = (uint64_t)-1;
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf, 1);
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(S->h[i >> 3] >> (8 * (i & 7)));
    }
}

static void blake2b_hash(uint8_t *out, size_t outlen, const void *in, size_t inlen) {
    blake2b_state S;
    blake2b_init(&S, outlen);
    blake2b_update(&S, (const uint8_t *)in, inlen);
    blake2b_final(&S, out, outlen);
}

static void blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t outlen_le[4];
    outlen_le[0] = (uint8_t)(outlen);
    outlen_le[1] = (uint8_t)(outlen >> 8);
    outlen_le[2] = (uint8_t)(outlen >> 16);
    outlen_le[3] = (uint8_t)(outlen >> 24);

    uint8_t buffer[BLAKE2B_OUTBYTES];
    uint8_t *initial_input = (uint8_t *)malloc(4 + inlen);
    if (!initial_input) return;
    memcpy(initial_input, outlen_le, 4);
    memcpy(initial_input + 4, in, inlen);

    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_hash(out, outlen, initial_input, 4 + inlen);
        free(initial_input);
        return;
    }

    blake2b_hash(buffer, BLAKE2B_OUTBYTES, initial_input, 4 + inlen);
    free(initial_input);

    size_t produced = 0;
    size_t to_write = (outlen < BLAKE2B_OUTBYTES) ? outlen : BLAKE2B_OUTBYTES;
    memcpy(out, buffer, to_write);
    produced += to_write;
    while (produced < outlen) {
        blake2b_hash(buffer, BLAKE2B_OUTBYTES, buffer, BLAKE2B_OUTBYTES);
        to_write = (outlen - produced < BLAKE2B_OUTBYTES) ? (outlen - produced) : BLAKE2B_OUTBYTES;
        memcpy(out + produced, buffer, to_write);
        produced += to_write;
    }
    memset(buffer, 0, sizeof(buffer));
}

// ------- Argon2 core (single-lane focused) -------
typedef struct { uint64_t v[ARGON2_BLOCK_QWORDS]; } argon2_block;

typedef struct {
    uint32_t pass;
    uint32_t lane;
    uint32_t slice;
    uint32_t index; // index within slice
} argon2_position;

static void block_copy(argon2_block *dst, const argon2_block *src) { memcpy(dst, src, ARGON2_BLOCK_SIZE); }
static void block_xor(argon2_block *dst, const argon2_block *src) {
    for (size_t i = 0; i < ARGON2_BLOCK_QWORDS; i++) dst->v[i] ^= src->v[i];
}

static void block_fill(const argon2_block *prev, const argon2_block *ref, argon2_block *next, int with_xor) {
    argon2_block r, z, old;
    if (with_xor) block_copy(&old, next);
    for (size_t i = 0; i < ARGON2_BLOCK_QWORDS; i++) r.v[i] = prev->v[i] ^ ref->v[i];
    block_copy(&z, &r);
#define G(a,b,c,d) \
    do { \
        a = a + b + 2 * (uint64_t)((uint32_t)a) * (uint64_t)((uint32_t)b); d = rotr64(d ^ a, 32); \
        c = c + d + 2 * (uint64_t)((uint32_t)c) * (uint64_t)((uint32_t)d); b = rotr64(b ^ c, 24); \
        a = a + b + 2 * (uint64_t)((uint32_t)a) * (uint64_t)((uint32_t)b); d = rotr64(d ^ a, 16); \
        c = c + d + 2 * (uint64_t)((uint32_t)c) * (uint64_t)((uint32_t)d); b = rotr64(b ^ c, 63); \
    } while (0)
    for (int i = 0; i < 8; i++) {
        uint64_t *v = z.v + i * 16;
        G(v[0], v[4], v[8], v[12]);
        G(v[1], v[5], v[9], v[13]);
        G(v[2], v[6], v[10], v[14]);
        G(v[3], v[7], v[11], v[15]);
        G(v[0], v[5], v[10], v[15]);
        G(v[1], v[6], v[11], v[12]);
        G(v[2], v[7], v[8], v[13]);
        G(v[3], v[4], v[9], v[14]);
    }
#undef G
    for (size_t i = 0; i < ARGON2_BLOCK_QWORDS; i++) {
        uint64_t v = z.v[i] ^ r.v[i];
        if (with_xor) v ^= old.v[i];
        next->v[i] = v;
    }
}

static uint32_t index_alpha(uint32_t pseudo_rand, const argon2_position *pos, uint32_t segment_length, uint32_t lane_length) {
    uint32_t reference_area_size;
    uint32_t start_pos;
    uint32_t curr_index = pos->index;
    if (pos->pass == 0) {
        start_pos = 0;
        if (pos->slice == 0) reference_area_size = curr_index - 1;
        else reference_area_size = pos->slice * segment_length + curr_index - 1;
    } else {
        start_pos = (pos->slice == 0) ? 0 : pos->slice * segment_length;
        reference_area_size = segment_length * 3 + curr_index - 1;
    }
    if (reference_area_size == 0) return 0;
    uint64_t rel = pseudo_rand;
    rel = (rel * rel) >> 32;
    uint32_t y = (uint32_t)((reference_area_size * rel) >> 32);
    uint32_t ref_index = (start_pos + reference_area_size - y) % lane_length;
    return ref_index;
}

static void fill_segment(argon2_block *memory, uint32_t lane_length, uint32_t segment_length, const argon2_position *pos, int data_independent) {
    uint32_t start_idx = (pos->pass == 0 && pos->slice == 0) ? 2 : 0;
    uint32_t curr_offset = pos->slice * segment_length + start_idx;
    uint32_t prev_offset = (curr_offset == 0) ? lane_length - 1 : curr_offset - 1;
    argon2_block address_block = {0};
    argon2_block input_block = {0};
    argon2_block zero_block = {0};
    uint32_t address_idx = ARGON2_BLOCK_QWORDS; // force init on first use
    if (data_independent) {
        input_block.v[0] = pos->pass;
        input_block.v[1] = pos->lane;
        input_block.v[2] = pos->slice;
        input_block.v[3] = lane_length;
        input_block.v[4] = ARGON2_SYNC_POINTS;
        input_block.v[5] = ARGON2_TYPE_ID;
    }
    for (uint32_t i = start_idx; i < segment_length; i++) {
        if (data_independent) {
            if (address_idx >= ARGON2_BLOCK_QWORDS) {
                input_block.v[6]++;
                argon2_block tmp;
                block_fill(&zero_block, &input_block, &tmp, 0);
                block_fill(&zero_block, &tmp, &address_block, 0);
                address_idx = 0;
            }
        }
        uint64_t pseudo_rand;
        if (data_independent) pseudo_rand = address_block.v[address_idx++];
        else pseudo_rand = memory[prev_offset].v[0];
        argon2_position cur = *pos;
        cur.index = i;
        uint32_t ref_index = index_alpha((uint32_t)pseudo_rand, &cur, segment_length, lane_length);
        argon2_block *ref = &memory[ref_index];
        argon2_block *prev = &memory[prev_offset];
        argon2_block *curr = &memory[curr_offset];
        int with_xor = (pos->pass != 0);
        block_fill(prev, ref, curr, with_xor);
        curr_offset++; if (curr_offset == lane_length) curr_offset = 0;
        prev_offset++; if (prev_offset == lane_length) prev_offset = 0;
    }
}

static int argon2_core(uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                       const uint8_t *pwd, size_t pwd_len, const uint8_t *salt, size_t salt_len,
                       uint8_t *out, size_t out_len) {
    if (parallelism == 0) return -1;
    if (parallelism != 1) return -2; // single-lane only in this build
    if (m_cost_kib < 8 * parallelism) return -3;
    if ((m_cost_kib / parallelism) % ARGON2_SYNC_POINTS != 0) return -3;
    if (out_len == 0 || out_len > 1024) return -4;

    const uint32_t lane_length = m_cost_kib / parallelism;
    const uint32_t segment_length = lane_length / ARGON2_SYNC_POINTS;
    argon2_block *memory = (argon2_block *)calloc(lane_length, sizeof(argon2_block));
    if (!memory) return -5;

    uint32_t pwd_len_le = (uint32_t)pwd_len;
    uint32_t salt_len_le = (uint32_t)salt_len;

    size_t H0_len = 6 * 4 + 4 + pwd_len + 4 + salt_len + 4 + 4;
    uint8_t *H0 = (uint8_t *)malloc(H0_len);
    if (!H0) { free(memory); return -5; }
    size_t off = 0;
    memcpy(H0 + off, &parallelism, 4); off += 4;
    uint32_t outlen_le = (uint32_t)out_len; memcpy(H0 + off, &outlen_le, 4); off += 4;
    uint32_t m_le = m_cost_kib; memcpy(H0 + off, &m_le, 4); off += 4;
    uint32_t t_le = t_cost; memcpy(H0 + off, &t_le, 4); off += 4;
    uint32_t version_le = ARGON2_VERSION; memcpy(H0 + off, &version_le, 4); off += 4;
    uint32_t type_le = ARGON2_TYPE_ID; memcpy(H0 + off, &type_le, 4); off += 4;
    memcpy(H0 + off, &pwd_len_le, 4); off += 4;
    memcpy(H0 + off, pwd, pwd_len); off += pwd_len;
    memcpy(H0 + off, &salt_len_le, 4); off += 4;
    memcpy(H0 + off, salt, salt_len); off += salt_len;
    uint32_t zero = 0;
    memcpy(H0 + off, &zero, 4); off += 4; // secret length
    memcpy(H0 + off, &zero, 4); off += 4; // ad length

    uint8_t H0_hash[BLAKE2B_OUTBYTES];
    blake2b_hash(H0_hash, BLAKE2B_OUTBYTES, H0, H0_len);
    free(H0);

    // Initial blocks for lane 0
    uint8_t tmp_input[BLAKE2B_OUTBYTES + 8];
    memcpy(tmp_input, H0_hash, BLAKE2B_OUTBYTES);
    uint32_t zero_lane = 0;
    uint32_t counter = 0;
    memcpy(tmp_input + BLAKE2B_OUTBYTES, &counter, 4);
    memcpy(tmp_input + BLAKE2B_OUTBYTES + 4, &zero_lane, 4);
    blake2b_long((uint8_t *)memory[0].v, ARGON2_BLOCK_SIZE, tmp_input, sizeof(tmp_input));
    counter = 1;
    memcpy(tmp_input + BLAKE2B_OUTBYTES, &counter, 4);
    blake2b_long((uint8_t *)memory[1].v, ARGON2_BLOCK_SIZE, tmp_input, sizeof(tmp_input));

    for (uint32_t pass = 0; pass < t_cost; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            argon2_position pos;
            pos.pass = pass; pos.lane = 0; pos.slice = slice; pos.index = 0;
            int data_indep = (pass == 0 && slice < 2);
            fill_segment(memory, lane_length, segment_length, &pos, data_indep);
        }
    }

    argon2_block final_block;
    block_copy(&final_block, &memory[lane_length - 1]);
    uint8_t final_hash[BLAKE2B_OUTBYTES];
    blake2b_hash(final_hash, BLAKE2B_OUTBYTES, (uint8_t *)final_block.v, ARGON2_BLOCK_SIZE);
    blake2b_long(out, out_len, final_hash, BLAKE2B_OUTBYTES);

    memset(final_hash, 0, sizeof(final_hash));
    free(memory);
    return 0;
}

int argon2id_hash_raw(uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                      const void *pwd, size_t pwd_len,
                      const void *salt, size_t salt_len,
                      void *out, size_t out_len) {
    return argon2_core(t_cost, m_cost_kib, parallelism,
                       (const uint8_t *)pwd, pwd_len, (const uint8_t *)salt, salt_len,
                       (uint8_t *)out, out_len);
}
