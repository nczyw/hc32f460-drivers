/**
 * @file  hc32_ll_aes_ex.c
 * @brief Incremental AES (ECB / CBC / CTR) built on the HC32F460 AES engine.
 *
 *        The AES hardware driver only exposes whole-buffer ECB encrypt/decrypt,
 *        so this layer keeps the chaining state in the caller owned context:
 *          - ECB/CBC encryption: input is accumulated into 16-byte blocks and
 *            PKCS#7 padding is applied in AES_Final_Ex();
 *          - ECB/CBC decryption: the last ciphertext block is held back until
 *            AES_Final_Ex() so the PKCS#7 padding can be verified and stripped;
 *          - CTR: counter block is encrypted by hardware to produce the
 *            keystream, any length is accepted and no padding is used.
 *        All block transformations still run in hardware; the CPU only does
 *        XOR, buffering, counter increment and padding.
 */

#include "hc32_ll_aes_ex.h"
#include "hc32_ll_utility.h"

#define AES_EX_BLOCK_SIZE           (16U)
#define AES_EX_STATE_IDLE           (0U)
#define AES_EX_STATE_ACTIVE         (1U)
#define AES_EX_STATE_DONE           (2U)

static void AES_Ex_MemCopy(uint8_t *pu8Dest, const uint8_t *pu8Src, uint32_t u32Len);
static void AES_Ex_Wipe(void *pBuffer, uint32_t u32Len);
static void AES_Ex_CtrIncrement(uint8_t *pu8Ctr);
static int32_t AES_Ex_EncryptBlock(const stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t AES_Ex_DecryptBlock(const stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t AES_Ex_CbcEncryptBlock(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t AES_Ex_CbcDecryptBlock(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t AES_Ex_Pkcs7Unpad(const uint8_t *pu8Block, uint32_t *pu32DataLen);
static void AES_Ex_Finish(stc_aes_ctx_t *pCtx);

/**
 * @brief  Copy a memory area (no overlap).
 */
static void AES_Ex_MemCopy(uint8_t *pu8Dest, const uint8_t *pu8Src, uint32_t u32Len)
{
    while (u32Len-- != 0U) {
        *pu8Dest++ = *pu8Src++;
    }
}

/**
 * @brief  Clear sensitive memory. The volatile pointer keeps the compiler from
 *         optimizing the stores away.
 */
static void AES_Ex_Wipe(void *pBuffer, uint32_t u32Len)
{
    volatile uint8_t *pu8Mem = (volatile uint8_t *)pBuffer;

    while (u32Len-- != 0U) {
        *pu8Mem++ = 0U;
    }
}

/**
 * @brief  Increment the low 64 bits of the CTR block in big-endian order.
 */
static void AES_Ex_CtrIncrement(uint8_t *pu8Ctr)
{
    uint32_t i;

    for (i = AES_EX_BLOCK_SIZE; i > 8U; i--) {
        pu8Ctr[i - 1U]++;
        if (pu8Ctr[i - 1U] != 0U) {
            break;
        }
    }
}

/**
 * @brief  Encrypt one 16-byte block with the hardware ECB engine.
 */
static int32_t AES_Ex_EncryptBlock(const stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out)
{
    return AES_Encrypt(pu8In, AES_EX_BLOCK_SIZE, pCtx->key, pCtx->key_size, pu8Out);
}

/**
 * @brief  Decrypt one 16-byte block with the hardware ECB engine.
 */
static int32_t AES_Ex_DecryptBlock(const stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out)
{
    return AES_Decrypt(pu8In, AES_EX_BLOCK_SIZE, pCtx->key, pCtx->key_size, pu8Out);
}

/**
 * @brief  CBC encryption of one block: C = E(P ^ IV), then IV = C.
 */
static int32_t AES_Ex_CbcEncryptBlock(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out)
{
    uint8_t  u8Temp[AES_EX_BLOCK_SIZE];
    uint32_t i;
    int32_t  i32Ret;

    for (i = 0U; i < AES_EX_BLOCK_SIZE; i++) {
        u8Temp[i] = pu8In[i] ^ pCtx->iv[i];
    }

    i32Ret = AES_Ex_EncryptBlock(pCtx, u8Temp, pu8Out);
    if (i32Ret == LL_OK) {
        AES_Ex_MemCopy(pCtx->iv, pu8Out, AES_EX_BLOCK_SIZE);
    }

    AES_Ex_Wipe(u8Temp, AES_EX_BLOCK_SIZE);
    return i32Ret;
}

/**
 * @brief  CBC decryption of one block: P = D(C) ^ IV, then IV = C.
 */
static int32_t AES_Ex_CbcDecryptBlock(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint8_t *pu8Out)
{
    uint8_t  u8Temp[AES_EX_BLOCK_SIZE];
    uint32_t i;
    int32_t  i32Ret;

    i32Ret = AES_Ex_DecryptBlock(pCtx, pu8In, u8Temp);
    if (i32Ret == LL_OK) {
        for (i = 0U; i < AES_EX_BLOCK_SIZE; i++) {
            pu8Out[i] = u8Temp[i] ^ pCtx->iv[i];
        }
        AES_Ex_MemCopy(pCtx->iv, pu8In, AES_EX_BLOCK_SIZE);
    }

    AES_Ex_Wipe(u8Temp, AES_EX_BLOCK_SIZE);
    return i32Ret;
}

/**
 * @brief  Verify and strip PKCS#7 padding of one decrypted block.
 * @param  [in]  pu8Block     16-byte decrypted block.
 * @param  [out] pu32DataLen  Number of real data bytes (1..16).
 * @retval LL_OK, or LL_ERR_INVD_PARAM when the padding is invalid.
 */
static int32_t AES_Ex_Pkcs7Unpad(const uint8_t *pu8Block, uint32_t *pu32DataLen)
{
    uint32_t u32Pad = pu8Block[AES_EX_BLOCK_SIZE - 1U];
    uint32_t i;

    if ((u32Pad == 0U) || (u32Pad > AES_EX_BLOCK_SIZE)) {
        return LL_ERR_INVD_PARAM;
    }

    for (i = AES_EX_BLOCK_SIZE - u32Pad; i < AES_EX_BLOCK_SIZE; i++) {
        if (pu8Block[i] != u32Pad) {
            return LL_ERR_INVD_PARAM;
        }
    }

    *pu32DataLen = AES_EX_BLOCK_SIZE - u32Pad;
    return LL_OK;
}

/**
 * @brief  Clear the context and reset the AES hardware registers.
 */
static void AES_Ex_Finish(stc_aes_ctx_t *pCtx)
{
    AES_Ex_Wipe(pCtx->key, sizeof(pCtx->key));
    AES_Ex_Wipe(pCtx->iv, sizeof(pCtx->iv));
    AES_Ex_Wipe(pCtx->ctr, sizeof(pCtx->ctr));
    AES_Ex_Wipe(pCtx->keystream, sizeof(pCtx->keystream));
    AES_Ex_Wipe(pCtx->buffer, sizeof(pCtx->buffer));
    pCtx->buffer_len = 0U;
    pCtx->ks_offset  = 0U;
    pCtx->state      = AES_EX_STATE_DONE;
    (void)AES_DeInit();
}

/**
 * @brief  Initialize the AES context for incremental calculation.
 */
int32_t AES_Init_Ex(stc_aes_ctx_t *pCtx, uint8_t u8Mode, uint8_t u8Dir,
                    const uint8_t *pu8Key, uint8_t u8KeySize, const uint8_t *pu8Iv)
{
    if ((pCtx == NULL) || (pu8Key == NULL)) {
        return LL_ERR_INVD_PARAM;
    }
    if ((u8Mode > AES_EX_MODE_CTR) || (u8Dir > AES_EX_DIR_DECRYPT)) {
        return LL_ERR_INVD_PARAM;
    }
    if (u8KeySize != AES_KEY_SIZE_16BYTE) {
        return LL_ERR_INVD_PARAM;
    }
    if ((u8Mode != AES_EX_MODE_ECB) && (pu8Iv == NULL)) {
        return LL_ERR_INVD_PARAM;
    }

    (void)AES_DeInit();

    AES_Ex_Wipe(pCtx, sizeof(stc_aes_ctx_t));

    pCtx->mode     = u8Mode;
    pCtx->dir      = (u8Mode == AES_EX_MODE_CTR) ? AES_EX_DIR_ENCRYPT : u8Dir;
    pCtx->key_size = u8KeySize;
    pCtx->state    = AES_EX_STATE_ACTIVE;

    AES_Ex_MemCopy(pCtx->key, pu8Key, AES_EX_BLOCK_SIZE);

    if (u8Mode == AES_EX_MODE_CBC) {
        AES_Ex_MemCopy(pCtx->iv, pu8Iv, AES_EX_BLOCK_SIZE);
    } else if (u8Mode == AES_EX_MODE_CTR) {
        AES_Ex_MemCopy(pCtx->ctr, pu8Iv, AES_EX_BLOCK_SIZE);
        pCtx->ks_offset = AES_EX_BLOCK_SIZE;   /* force keystream generation */
    }

    return LL_OK;
}

/**
 * @brief  Append data to the AES calculation.
 */
int32_t AES_Update_Ex(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint32_t u32InLen,
                      uint8_t *pu8Out, uint32_t *pu32OutLen)
{
    uint32_t u32In    = 0U;
    uint32_t u32Out   = 0U;
    uint32_t u32Space;
    uint32_t u32Copy;
    int32_t  i32Ret;

    if ((pCtx == NULL) || (pu32OutLen == NULL)) {
        return LL_ERR_INVD_PARAM;
    }

    *pu32OutLen = 0U;

    if (pCtx->state != AES_EX_STATE_ACTIVE) {
        return LL_ERR_INVD_PARAM;
    }
    if ((u32InLen != 0U) && ((pu8In == NULL) || (pu8Out == NULL))) {
        return LL_ERR_INVD_PARAM;
    }
    if (u32InLen == 0U) {
        return LL_OK;
    }

    if (pCtx->mode == AES_EX_MODE_CTR) {
        while (u32In < u32InLen) {
            if (pCtx->ks_offset >= AES_EX_BLOCK_SIZE) {
                i32Ret = AES_Ex_EncryptBlock(pCtx, pCtx->ctr, pCtx->keystream);
                if (i32Ret != LL_OK) {
                    return i32Ret;
                }
                AES_Ex_CtrIncrement(pCtx->ctr);
                pCtx->ks_offset = 0U;
            }
            pu8Out[u32Out++] = pu8In[u32In++] ^ pCtx->keystream[pCtx->ks_offset++];
        }
        *pu32OutLen = u32Out;
        return LL_OK;
    }

    if (pCtx->dir == AES_EX_DIR_ENCRYPT) {
        while (u32In < u32InLen) {
            u32Space = AES_EX_BLOCK_SIZE - pCtx->buffer_len;
            u32Copy  = ((u32InLen - u32In) < u32Space) ? (u32InLen - u32In) : u32Space;

            AES_Ex_MemCopy(&pCtx->buffer[pCtx->buffer_len], &pu8In[u32In], u32Copy);
            pCtx->buffer_len += u32Copy;
            u32In += u32Copy;

            if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
                if (pCtx->mode == AES_EX_MODE_CBC) {
                    i32Ret = AES_Ex_CbcEncryptBlock(pCtx, pCtx->buffer, &pu8Out[u32Out]);
                } else {
                    i32Ret = AES_Ex_EncryptBlock(pCtx, pCtx->buffer, &pu8Out[u32Out]);
                }
                if (i32Ret != LL_OK) {
                    return i32Ret;
                }
                pCtx->buffer_len = 0U;
                u32Out += AES_EX_BLOCK_SIZE;
            }
        }
    } else {
        while (u32In < u32InLen) {
            /* Hold one ciphertext block back so Final can verify the padding. */
            if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
                if (pCtx->mode == AES_EX_MODE_CBC) {
                    i32Ret = AES_Ex_CbcDecryptBlock(pCtx, pCtx->buffer, &pu8Out[u32Out]);
                } else {
                    i32Ret = AES_Ex_DecryptBlock(pCtx, pCtx->buffer, &pu8Out[u32Out]);
                }
                if (i32Ret != LL_OK) {
                    return i32Ret;
                }
                pCtx->buffer_len = 0U;
                u32Out += AES_EX_BLOCK_SIZE;
            }

            u32Space = AES_EX_BLOCK_SIZE - pCtx->buffer_len;
            u32Copy  = ((u32InLen - u32In) < u32Space) ? (u32InLen - u32In) : u32Space;
            AES_Ex_MemCopy(&pCtx->buffer[pCtx->buffer_len], &pu8In[u32In], u32Copy);
            pCtx->buffer_len += u32Copy;
            u32In += u32Copy;
        }
    }

    *pu32OutLen = u32Out;
    return LL_OK;
}

/**
 * @brief  Finalize the AES calculation.
 */
int32_t AES_Final_Ex(stc_aes_ctx_t *pCtx, uint8_t *pu8Out, uint32_t *pu32OutLen)
{
    uint8_t  u8Temp[AES_EX_BLOCK_SIZE];
    uint32_t u32DataLen;
    uint32_t u32Pad;
    uint32_t i;
    int32_t  i32Ret;

    if ((pCtx == NULL) || (pu8Out == NULL) || (pu32OutLen == NULL)) {
        return LL_ERR_INVD_PARAM;
    }

    *pu32OutLen = 0U;

    if (pCtx->state != AES_EX_STATE_ACTIVE) {
        return LL_ERR_INVD_PARAM;
    }

    if (pCtx->mode == AES_EX_MODE_CTR) {
        AES_Ex_Finish(pCtx);
        return LL_OK;
    }

    if (pCtx->dir == AES_EX_DIR_ENCRYPT) {
        /* PKCS#7: always add 1..16 bytes of padding. */
        u32Pad = AES_EX_BLOCK_SIZE - pCtx->buffer_len;
        for (i = pCtx->buffer_len; i < AES_EX_BLOCK_SIZE; i++) {
            pCtx->buffer[i] = (uint8_t)u32Pad;
        }

        if (pCtx->mode == AES_EX_MODE_CBC) {
            i32Ret = AES_Ex_CbcEncryptBlock(pCtx, pCtx->buffer, pu8Out);
        } else {
            i32Ret = AES_Ex_EncryptBlock(pCtx, pCtx->buffer, pu8Out);
        }
        if (i32Ret != LL_OK) {
            return i32Ret;
        }

        *pu32OutLen = AES_EX_BLOCK_SIZE;
        AES_Ex_Finish(pCtx);
        return LL_OK;
    }

    /* Decryption: the last ciphertext block was held back by Update. */
    if (pCtx->buffer_len != AES_EX_BLOCK_SIZE) {
        return LL_ERR_INVD_PARAM;
    }

    if (pCtx->mode == AES_EX_MODE_CBC) {
        i32Ret = AES_Ex_CbcDecryptBlock(pCtx, pCtx->buffer, u8Temp);
    } else {
        i32Ret = AES_Ex_DecryptBlock(pCtx, pCtx->buffer, u8Temp);
    }
    if (i32Ret != LL_OK) {
        AES_Ex_Wipe(u8Temp, AES_EX_BLOCK_SIZE);
        return i32Ret;
    }

    i32Ret = AES_Ex_Pkcs7Unpad(u8Temp, &u32DataLen);
    if (i32Ret != LL_OK) {
        AES_Ex_Wipe(u8Temp, AES_EX_BLOCK_SIZE);
        return i32Ret;
    }

    AES_Ex_MemCopy(pu8Out, u8Temp, u32DataLen);
    AES_Ex_Wipe(u8Temp, AES_EX_BLOCK_SIZE);

    *pu32OutLen = u32DataLen;
    AES_Ex_Finish(pCtx);
    return LL_OK;
}
