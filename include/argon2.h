#pragma once
#include <stddef.h>
#include <stdint.h>

int argon2id_hash_raw(uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                      const void *pwd, size_t pwd_len,
                      const void *salt, size_t salt_len,
                      void *out, size_t out_len);
