#pragma once
#include "common.h"

// LSA decryption (LSASS memory path)
Bytes lsa_decrypt(const uint8_t* enc, size_t enc_len,
                  const uint8_t* aes_key, size_t aes_key_len,
                  const uint8_t* des_key, size_t des_key_len,
                  const uint8_t* iv, size_t iv_len);

// Hash functions via CNG
Bytes sha1_hash(const uint8_t* data, size_t data_len);

// AES-128-CBC decryption
Bytes aes128_cbc_decrypt(const uint8_t* key, size_t key_len,
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* data, size_t data_len);

// 3DES-CBC decryption
Bytes des3_cbc_decrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* iv8, size_t iv_len,
                       const uint8_t* ct, size_t ct_len);

// AES-CFB128 decryption (manual ECB+XOR)
Bytes aes_cfb128_decrypt(const uint8_t* ct, size_t ct_len,
                         const uint8_t* key, size_t key_len,
                         const uint8_t* iv, size_t iv_len);
