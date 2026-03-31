#include "crypto.h"

// ================================================================
// 3DES-CBC decryption
// ================================================================
Bytes des3_cbc_decrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* iv8, size_t iv_len,
                       const uint8_t* ct, size_t ct_len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE bkey = NULL;
    Bytes out;
    MSVCRT$memset(&out, 0, sizeof(out));

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_3DES_ALGORITHM, NULL, 0)))
        return out;

    wchar_t cbc_mode[] = BCRYPT_CHAIN_MODE_CBC;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)cbc_mode, (ULONG)sizeof(cbc_mode), 0)))
        goto cleanup_alg;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &bkey, NULL, 0,
        (PUCHAR)key, (ULONG)key_len, 0)))
        goto cleanup_alg;

    uint8_t iv_copy[8] = {0};
    size_t copy_iv = iv_len < 8 ? iv_len : 8;
    MSVCRT$memcpy(iv_copy, iv8, copy_iv);

    out = Bytes_zeros(ct_len);
    ULONG result_len = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(bkey,
        (PUCHAR)ct, (ULONG)ct_len, NULL,
        iv_copy, 8,
        out.data, (ULONG)out.size, &result_len, 0))) {
        Bytes_free(&out);
    } else {
        out.size = result_len;
    }

    BCryptDestroyKey(bkey);
cleanup_alg:
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// ================================================================
// AES-CFB128 decryption (manual ECB+XOR, BCrypt only supports CFB8)
// ================================================================
Bytes aes_cfb128_decrypt(const uint8_t* ct, size_t ct_len,
                         const uint8_t* key, size_t key_len,
                         const uint8_t* iv, size_t iv_len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE bkey = NULL;
    Bytes out;
    MSVCRT$memset(&out, 0, sizeof(out));

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return out;

    wchar_t ecb_mode[] = BCRYPT_CHAIN_MODE_ECB;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)ecb_mode, (ULONG)sizeof(ecb_mode), 0)))
        goto cleanup_alg;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &bkey, NULL, 0,
        (PUCHAR)key, (ULONG)key_len, 0)))
        goto cleanup_alg;

    out = Bytes_alloc(ct_len);
    out.size = 0;

    uint8_t feedback[16] = {0};
    {
        size_t copy_iv = iv_len < 16 ? iv_len : 16;
        MSVCRT$memcpy(feedback, iv, copy_iv);
    }

    size_t off;
    for (off = 0; off < ct_len; off += 16) {
        uint8_t encrypted[16] = {0};
        uint8_t fb_copy[16];
        MSVCRT$memcpy(fb_copy, feedback, 16);
        ULONG result_len = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(bkey, fb_copy, 16, NULL,
            NULL, 0, encrypted, 16, &result_len, 0)))
            break;

        size_t block_len = ct_len - off;
        if (block_len > 16) block_len = 16;
        size_t i;
        for (i = 0; i < block_len; i++)
            out.data[out.size++] = encrypted[i] ^ ct[off + i];

        MSVCRT$memset(feedback, 0, 16);
        MSVCRT$memcpy(feedback, ct + off, block_len);
    }

    BCryptDestroyKey(bkey);
cleanup_alg:
    BCryptCloseAlgorithmProvider(alg, 0);
    if (out.size < ct_len) Bytes_free(&out);
    return out;
}

// ================================================================
// LSA decryption dispatcher
// ================================================================
Bytes lsa_decrypt(const uint8_t* enc, size_t enc_len,
                  const uint8_t* aes_key, size_t aes_key_len,
                  const uint8_t* des_key, size_t des_key_len,
                  const uint8_t* iv, size_t iv_len) {
    Bytes empty;
    MSVCRT$memset(&empty, 0, sizeof(empty));
    if (!enc || enc_len == 0) return empty;

    if (enc_len % 8 != 0) {
        return aes_cfb128_decrypt(enc, enc_len, aes_key, aes_key_len, iv, iv_len);
    } else {
        size_t iv8_len = iv_len < 8 ? iv_len : 8;
        return des3_cbc_decrypt(des_key, des_key_len, iv, iv8_len, enc, enc_len);
    }
}
