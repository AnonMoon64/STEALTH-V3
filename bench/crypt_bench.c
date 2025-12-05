#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Simple micro-benchmark for AES-GCM encrypt vs XOR for a given file
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <file> [iterations]\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int iterations = argc >= 3 ? atoi(argv[2]) : 10;
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, size, f); fclose(f);

    unsigned char key[32]; RAND_bytes(key, sizeof(key));
    unsigned char iv[12]; RAND_bytes(iv, sizeof(iv));

    clock_t t0 = clock();
    for (int it = 0; it < iterations; ++it) {
        // XOR
        unsigned char *tmp = malloc(size);
        for (long i = 0; i < size; ++i) tmp[i] = buf[i] ^ key[i % 32];
        free(tmp);
    }
    clock_t t1 = clock();
    double xor_time = (double)(t1 - t0) / CLOCKS_PER_SEC;

    t0 = clock();
    for (int it = 0; it < iterations; ++it) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outlen = 0;
        unsigned char *out = malloc(size + 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, out, &outlen, buf, (int)size);
        int clen = outlen;
        EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
        clen += outlen;
        unsigned char tag[16]; EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        EVP_CIPHER_CTX_free(ctx);
        free(out);
    }
    t1 = clock();
    double aes_time = (double)(t1 - t0) / CLOCKS_PER_SEC;

    printf("File: %s, size=%ld, iterations=%d\n", path, size, iterations);
    printf("XOR total time: %.3fs\n", xor_time);
    printf("AES-GCM total time: %.3fs\n", aes_time);

    free(buf);
    return 0;
}
