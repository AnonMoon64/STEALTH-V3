#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "argon2.h"

// Self-contained ChaCha20 + Poly1305 (no OpenSSL) + Argon2id (vendored).

// -------- Secure zero --------
static void secure_zero(void *ptr, size_t len) {
    if (!ptr || !len) return;
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

// -------- Random helper (nonce) --------
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")
static int random_bytes(uint8_t *buf, size_t len) {
    return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
}
#else
#include <stdio.h>
#include <time.h>
static int random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    return got == len ? 0 : -1;
}
#endif

// -------- ChaCha20 core --------
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    memcpy(out, in, 64);
    for (i = 0; i < 10; i++) {
        // column rounds
        out[0] += out[4]; out[12] = rotl32(out[12] ^ out[0], 16);
        out[8] += out[12]; out[4] = rotl32(out[4] ^ out[8], 12);
        out[0] += out[4]; out[12] = rotl32(out[12] ^ out[0], 8);
        out[8] += out[12]; out[4] = rotl32(out[4] ^ out[8], 7);

        out[1] += out[5]; out[13] = rotl32(out[13] ^ out[1], 16);
        out[9] += out[13]; out[5] = rotl32(out[5] ^ out[9], 12);
        out[1] += out[5]; out[13] = rotl32(out[13] ^ out[1], 8);
        out[9] += out[13]; out[5] = rotl32(out[5] ^ out[9], 7);

        out[2] += out[6]; out[14] = rotl32(out[14] ^ out[2], 16);
        out[10] += out[14]; out[6] = rotl32(out[6] ^ out[10], 12);
        out[2] += out[6]; out[14] = rotl32(out[14] ^ out[2], 8);
        out[10] += out[14]; out[6] = rotl32(out[6] ^ out[10], 7);

        out[3] += out[7]; out[15] = rotl32(out[15] ^ out[3], 16);
        out[11] += out[15]; out[7] = rotl32(out[7] ^ out[11], 12);
        out[3] += out[7]; out[15] = rotl32(out[15] ^ out[3], 8);
        out[11] += out[15]; out[7] = rotl32(out[7] ^ out[11], 7);

        // diagonal rounds
        out[0] += out[5]; out[15] = rotl32(out[15] ^ out[0], 16);
        out[10] += out[15]; out[5] = rotl32(out[5] ^ out[10], 12);
        out[0] += out[5]; out[15] = rotl32(out[15] ^ out[0], 8);
        out[10] += out[15]; out[5] = rotl32(out[5] ^ out[10], 7);

        out[1] += out[6]; out[12] = rotl32(out[12] ^ out[1], 16);
        out[11] += out[12]; out[6] = rotl32(out[6] ^ out[11], 12);
        out[1] += out[6]; out[12] = rotl32(out[12] ^ out[1], 8);
        out[11] += out[12]; out[6] = rotl32(out[6] ^ out[11], 7);

        out[2] += out[7]; out[13] = rotl32(out[13] ^ out[2], 16);
        out[8] += out[13]; out[7] = rotl32(out[7] ^ out[8], 12);
        out[2] += out[7]; out[13] = rotl32(out[13] ^ out[2], 8);
        out[8] += out[13]; out[7] = rotl32(out[7] ^ out[8], 7);

        out[3] += out[4]; out[14] = rotl32(out[14] ^ out[3], 16);
        out[9] += out[14]; out[4] = rotl32(out[4] ^ out[9], 12);
        out[3] += out[4]; out[14] = rotl32(out[14] ^ out[3], 8);
        out[9] += out[14]; out[4] = rotl32(out[4] ^ out[9], 7);
    }
    for (i = 0; i < 16; i++) out[i] += in[i];
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16];
    const char *constants = "expand 32-byte k";
    memcpy(state, constants, 16);
    state[4] = ((uint32_t)key[0]) | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24);
    state[5] = ((uint32_t)key[4]) | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24);
    state[6] = ((uint32_t)key[8]) | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24);
    state[7] = ((uint32_t)key[12]) | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24);
    state[8] = ((uint32_t)key[16]) | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    state[9] = ((uint32_t)key[20]) | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    state[10] = ((uint32_t)key[24]) | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    state[11] = ((uint32_t)key[28]) | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);
    state[12] = counter;
    state[13] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) | ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    state[14] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) | ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    state[15] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) | ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);

    uint8_t block[64];
    size_t offset = 0;
    while (offset < len) {
        uint32_t working[16];
        chacha20_block(working, state);
        for (int i = 0; i < 16; i++) {
            block[4 * i] = working[i] & 0xff;
            block[4 * i + 1] = (working[i] >> 8) & 0xff;
            block[4 * i + 2] = (working[i] >> 16) & 0xff;
            block[4 * i + 3] = (working[i] >> 24) & 0xff;
        }
        size_t block_len = (len - offset) < 64 ? (len - offset) : 64;
        for (size_t j = 0; j < block_len; j++) {
            out[offset + j] = in[offset + j] ^ block[j];
        }
        offset += block_len;
        state[12]++;
    }
    secure_zero(block, sizeof(block));
}

// -------- Poly1305 --------
static void poly1305_mac(uint8_t tag[16], const uint8_t *msg, size_t msg_len, const uint8_t key[32]) {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    uint32_t c, g0, g1, g2, g3, g4;
    uint64_t f0, f1, f2, f3;

    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    r0 = ((uint32_t)key[0] | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24)) & 0x3ffffff;
    r1 = (((uint32_t)key[3] >> 2) | ((uint32_t)key[4] << 6) | ((uint32_t)key[5] << 14) | ((uint32_t)key[6] << 22)) & 0x3ffff03;
    r2 = (((uint32_t)key[6] >> 4) | ((uint32_t)key[7] << 4) | ((uint32_t)key[8] << 12) | ((uint32_t)key[9] << 20)) & 0x3ffc0ff;
    r3 = (((uint32_t)key[9] >> 6) | ((uint32_t)key[10] << 2) | ((uint32_t)key[11] << 10) | ((uint32_t)key[12] << 18)) & 0x3f03fff;
    r4 = (((uint32_t)key[12] >> 8) | ((uint32_t)key[13] << 0) | ((uint32_t)key[14] << 8) | ((uint32_t)key[15] << 16)) & 0x00fffff;

    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

    const uint8_t *p = msg;
    while (msg_len) {
        uint32_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
        size_t rem = msg_len;
        if (rem >= 16) rem = 16;
        uint8_t block[16] = {0};
        memcpy(block, p, rem);
        t0 = ((uint32_t)block[0] | ((uint32_t)block[1] << 8) | ((uint32_t)block[2] << 16) | ((uint32_t)block[3] << 24)) & 0x3ffffff;
        t1 = (((uint32_t)block[3] >> 2) | ((uint32_t)block[4] << 6) | ((uint32_t)block[5] << 14) | ((uint32_t)block[6] << 22)) & 0x3ffffff;
        t2 = (((uint32_t)block[6] >> 4) | ((uint32_t)block[7] << 4) | ((uint32_t)block[8] << 12) | ((uint32_t)block[9] << 20)) & 0x3ffffff;
        t3 = (((uint32_t)block[9] >> 6) | ((uint32_t)block[10] << 2) | ((uint32_t)block[11] << 10) | ((uint32_t)block[12] << 18)) & 0x3ffffff;
        t4 = (((uint32_t)block[12] >> 8) | ((uint32_t)block[13] << 0) | ((uint32_t)block[14] << 8) | ((uint32_t)block[15] << 16)) | (1 << 24);

        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = (h0 >> 26); h0 &= 0x3ffffff; h1 += c;

        p += rem;
        msg_len -= rem;
    }

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    f0 = ((uint64_t)h0 | ((uint64_t)h1 << 26)) + ((uint64_t)key[16] | ((uint64_t)key[17] << 8) | ((uint64_t)key[18] << 16) | ((uint64_t)key[19] << 24));
    f1 = (((uint64_t)h1 >> 6) | ((uint64_t)h2 << 20)) + ((uint64_t)key[20] | ((uint64_t)key[21] << 8) | ((uint64_t)key[22] << 16) | ((uint64_t)key[23] << 24));
    f2 = (((uint64_t)h2 >> 12) | ((uint64_t)h3 << 14)) + ((uint64_t)key[24] | ((uint64_t)key[25] << 8) | ((uint64_t)key[26] << 16) | ((uint64_t)key[27] << 24));
    f3 = (((uint64_t)h3 >> 18) | ((uint64_t)h4 << 8)) + ((uint64_t)key[28] | ((uint64_t)key[29] << 8) | ((uint64_t)key[30] << 16) | ((uint64_t)key[31] << 24));

    tag[0] = (uint8_t)f0; tag[1] = (uint8_t)(f0 >> 8); tag[2] = (uint8_t)(f0 >> 16); tag[3] = (uint8_t)(f0 >> 24);
    tag[4] = (uint8_t)f1; tag[5] = (uint8_t)(f1 >> 8); tag[6] = (uint8_t)(f1 >> 16); tag[7] = (uint8_t)(f1 >> 24);
    tag[8] = (uint8_t)f2; tag[9] = (uint8_t)(f2 >> 8); tag[10] = (uint8_t)(f2 >> 16); tag[11] = (uint8_t)(f2 >> 24);
    tag[12] = (uint8_t)f3; tag[13] = (uint8_t)(f3 >> 8); tag[14] = (uint8_t)(f3 >> 16); tag[15] = (uint8_t)(f3 >> 24);
    secure_zero(&r0, sizeof(r0));
}

// -------- ChaCha20-Poly1305 AEAD --------
static int chacha20poly1305_encrypt(const uint8_t *pt, size_t pt_len,
                                    const uint8_t *key32,
                                    const uint8_t *nonce12,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *ct_out, uint8_t tag_out[16]) {
    uint8_t poly_key[32];
    uint8_t zeros[64] = {0};
    chacha20_xor(poly_key, zeros, 32, key32, nonce12, 0);
    chacha20_xor(ct_out, pt, pt_len, key32, nonce12, 1);

    // Build Poly1305 input: aad || pad16 || ciphertext || pad16 || aad_len || ct_len
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + pt_len + ct_pad + 16;
    uint8_t *mac_buf = (uint8_t *)malloc(mac_len);
    if (!mac_buf) { secure_zero(poly_key, sizeof(poly_key)); return -1; }
    uint8_t *p = mac_buf;
    if (aad && aad_len) { memcpy(p, aad, aad_len); p += aad_len; }
    if (aad_pad) { memset(p, 0, aad_pad); p += aad_pad; }
    if (pt_len) { memcpy(p, ct_out, pt_len); p += pt_len; }
    if (ct_pad) { memset(p, 0, ct_pad); p += ct_pad; }
    uint64_t aad_bits = (uint64_t)aad_len;
    uint64_t ct_bits = (uint64_t)pt_len;
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(aad_bits >> (8 * i)); }
    for (int i = 0; i < 8; i++) { p[8 + i] = (uint8_t)(ct_bits >> (8 * i)); }
    poly1305_mac(tag_out, mac_buf, mac_len, poly_key);
    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(mac_buf, mac_len);
    free(mac_buf);
    return 0;
}

static int chacha20poly1305_decrypt(const uint8_t *ct, size_t ct_len,
                                    const uint8_t *key32,
                                    const uint8_t *nonce12,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t tag[16],
                                    uint8_t *pt_out) {
    uint8_t poly_key[32];
    uint8_t zeros[64] = {0};
    chacha20_xor(poly_key, zeros, 32, key32, nonce12, 0);

    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    size_t ct_pad = (16 - (ct_len % 16)) % 16;
    size_t mac_len = aad_len + aad_pad + ct_len + ct_pad + 16;
    uint8_t *mac_buf = (uint8_t *)malloc(mac_len);
    if (!mac_buf) { secure_zero(poly_key, sizeof(poly_key)); return -1; }
    uint8_t *p = mac_buf;
    if (aad && aad_len) { memcpy(p, aad, aad_len); p += aad_len; }
    if (aad_pad) { memset(p, 0, aad_pad); p += aad_pad; }
    if (ct_len) { memcpy(p, ct, ct_len); p += ct_len; }
    if (ct_pad) { memset(p, 0, ct_pad); p += ct_pad; }
    uint64_t aad_bits = (uint64_t)aad_len;
    uint64_t ct_bits = (uint64_t)ct_len;
    for (int i = 0; i < 8; i++) { p[i] = (uint8_t)(aad_bits >> (8 * i)); }
    for (int i = 0; i < 8; i++) { p[8 + i] = (uint8_t)(ct_bits >> (8 * i)); }
    uint8_t calc_tag[16];
    poly1305_mac(calc_tag, mac_buf, mac_len, poly_key);
    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(mac_buf, mac_len);
    free(mac_buf);
    if (memcmp(calc_tag, tag, 16) != 0) {
        secure_zero(calc_tag, sizeof(calc_tag));
        return -1;
    }
    secure_zero(calc_tag, sizeof(calc_tag));
    chacha20_xor(pt_out, ct, ct_len, key32, nonce12, 1);
    return 0;
}

// -------- API --------

int crypto_argon2id_derive(const uint8_t *pwd, size_t pwd_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                           uint8_t *out_key, size_t out_key_len) {
    if (!pwd || !salt || !out_key || out_key_len != CRYPTO_KEY_LEN) return -1;
    return argon2id_hash_raw(t_cost, m_cost_kib, parallelism, pwd, pwd_len, salt, salt_len, out_key, out_key_len);
}

int crypto_chacha20_poly1305_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *key32,
                                     const uint8_t *aad, size_t aad_len,
                                     CryptoEnvelope *env,
                                     uint8_t *out_ciphertext) {
    if (!plaintext || !key32 || !env || !out_ciphertext) return -1;
    if (random_bytes(env->nonce, CRYPTO_NONCE_LEN) != 0) return -1;
    env->version = CRYPTO_VERSION;
    return chacha20poly1305_encrypt(plaintext, plaintext_len, key32, env->nonce, aad, aad_len, out_ciphertext, env->tag);
}

int crypto_chacha20_poly1305_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t *key32,
                                     const uint8_t *aad, size_t aad_len,
                                     const CryptoEnvelope *env,
                                     uint8_t *out_plaintext) {
    if (!ciphertext || !key32 || !env || !out_plaintext) return -1;
    if (env->version != CRYPTO_VERSION) return -1;
    return chacha20poly1305_decrypt(ciphertext, ciphertext_len, key32, env->nonce, aad, aad_len, env->tag, out_plaintext);
}

int crypto_encrypt_with_pass(const uint8_t *plaintext, size_t plaintext_len,
                             const uint8_t *pass, size_t pass_len,
                             const uint8_t *aad, size_t aad_len,
                             uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                             uint8_t *salt_out,
                             uint8_t *nonce_out,
                             uint8_t *tag_out,
                             uint8_t *ciphertext_out) {
    uint8_t key[CRYPTO_KEY_LEN];
    if (crypto_argon2id_derive(pass, pass_len, salt_out, CRYPTO_SALT_LEN, t_cost, m_cost_kib, parallelism, key, sizeof(key)) != 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }
    CryptoEnvelope env = {0};
    env.version = CRYPTO_VERSION;
    env.t_cost = t_cost;
    env.m_cost_kib = m_cost_kib;
    env.parallelism = parallelism;
    memcpy(env.salt, salt_out, CRYPTO_SALT_LEN);
    int rc = crypto_chacha20_poly1305_encrypt(plaintext, plaintext_len, key, aad, aad_len, &env, ciphertext_out);
    if (rc == 0) {
        memcpy(nonce_out, env.nonce, CRYPTO_NONCE_LEN);
        memcpy(tag_out, env.tag, CRYPTO_TAG_LEN);
    }
    secure_zero(key, sizeof(key));
    return rc;
}

int crypto_decrypt_with_pass(const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t *pass, size_t pass_len,
                             const uint8_t *aad, size_t aad_len,
                             const CryptoEnvelope *env,
                             uint8_t *plaintext_out) {
    uint8_t key[CRYPTO_KEY_LEN];
    if (crypto_argon2id_derive(pass, pass_len, env->salt, CRYPTO_SALT_LEN, env->t_cost, env->m_cost_kib, env->parallelism, key, sizeof(key)) != 0) {
        secure_zero(key, sizeof(key));
        return -1;
    }
    int rc = crypto_chacha20_poly1305_decrypt(ciphertext, ciphertext_len, key, aad, aad_len, env, plaintext_out);
    secure_zero(key, sizeof(key));
    return rc;
}
