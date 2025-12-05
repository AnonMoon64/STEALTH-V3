#include <stddef.h>
#include <stdint.h>

#define CRYPTO_VERSION 2
#define CRYPTO_SALT_LEN 16
#define CRYPTO_NONCE_LEN 12
#define CRYPTO_TAG_LEN 16
#define CRYPTO_KEY_LEN 32

// Envelope for ChaCha20-Poly1305 + Argon2id-derived key
// Layout: [version][argon2 params][salt][nonce][tag][ciphertext]
// argon2 params are serialized for forward compatibility.
typedef struct {
    uint32_t version;
    uint32_t t_cost;       // iterations
    uint32_t m_cost_kib;   // memory cost in KiB
    uint32_t parallelism;  // lanes (currently enforced =1)
    uint8_t salt[CRYPTO_SALT_LEN];
    uint8_t nonce[CRYPTO_NONCE_LEN];
    uint8_t tag[CRYPTO_TAG_LEN];
    const uint8_t *ciphertext; // not owned; points into a buffer passed by caller
    size_t ciphertext_len;
} CryptoEnvelope;

int crypto_argon2id_derive(const uint8_t *pwd, size_t pwd_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                           uint8_t *out_key, size_t out_key_len);

int crypto_chacha20_poly1305_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                                     const uint8_t *key32,
                                     const uint8_t *aad, size_t aad_len,
                                     CryptoEnvelope *env,
                                     uint8_t *out_ciphertext /* same length as plaintext */);

int crypto_chacha20_poly1305_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                                     const uint8_t *key32,
                                     const uint8_t *aad, size_t aad_len,
                                     const CryptoEnvelope *env,
                                     uint8_t *out_plaintext /* same length as ciphertext */);

// Convenience: build envelope + ciphertext in a single buffer (ciphertext follows header)
int crypto_encrypt_with_pass(const uint8_t *plaintext, size_t plaintext_len,
                             const uint8_t *pass, size_t pass_len,
                             const uint8_t *aad, size_t aad_len,
                             uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                             uint8_t *salt_out,
                             uint8_t *nonce_out,
                             uint8_t *tag_out,
                             uint8_t *ciphertext_out);

int crypto_decrypt_with_pass(const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t *pass, size_t pass_len,
                             const uint8_t *aad, size_t aad_len,
                             const CryptoEnvelope *env,
                             uint8_t *plaintext_out);
