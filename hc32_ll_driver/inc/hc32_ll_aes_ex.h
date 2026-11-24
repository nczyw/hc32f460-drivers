#ifndef __HC32_LL_AES_EX_H__
#define __HC32_LL_AES_EX_H__

#include "hc32_ll_aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cipher mode */
#define AES_EX_MODE_ECB             (0U)
#define AES_EX_MODE_CBC             (1U)
#define AES_EX_MODE_CTR             (2U)

/* Cipher direction (ignored in CTR mode) */
#define AES_EX_DIR_ENCRYPT          (0U)
#define AES_EX_DIR_DECRYPT          (1U)

/*
 * AES context structure for incremental calculation.
 * All state is kept here (stack/static/heap), no file level globals are used.
 * NOTE: The AES hardware is a single chip-wide instance. Concurrent use from
 *       several tasks still needs an external mutex.
 */
typedef struct {
    uint8_t  mode;              /* AES_EX_MODE_xxx                        */
    uint8_t  dir;               /* AES_EX_DIR_xxx                         */
    uint8_t  state;             /* 0=uninitialized, 1=active, 2=finished  */
    uint8_t  key_size;          /* AES_KEY_SIZE_16BYTE                    */
    uint8_t  key[16];           /* AES-128 key                            */
    uint8_t  iv[16];            /* CBC: chaining value                    */
    uint8_t  ctr[16];           /* CTR: 8B nonce + 8B counter (big endian)*/
    uint8_t  keystream[16];     /* CTR: current keystream block           */
    uint8_t  buffer[16];        /* Pending input block                    */
    uint32_t buffer_len;        /* Valid bytes in buffer                  */
    uint32_t ks_offset;         /* CTR: consumed bytes of keystream       */
} stc_aes_ctx_t;

/* ==================== AES Incremental API ==================== */

/**
 * @brief  Initialize the AES context for incremental calculation.
 *         The AES hardware only supports AES-128 (AES_KEY_SIZE_16BYTE).
 * @param  [out] pCtx       Pointer to the AES context structure.
 * @param  [in]  u8Mode     AES_EX_MODE_ECB, AES_EX_MODE_CBC or AES_EX_MODE_CTR.
 * @param  [in]  u8Dir      AES_EX_DIR_ENCRYPT or AES_EX_DIR_DECRYPT (CTR ignores it).
 * @param  [in]  pu8Key     Pointer to the 16-byte key.
 * @param  [in]  u8KeySize  Key size, must be AES_KEY_SIZE_16BYTE.
 * @param  [in]  pu8Iv      16-byte IV (CBC) or 16-byte nonce+counter (CTR).
 *                          May be NULL only for ECB.
 * @retval LL_OK on success, other values indicate error codes.
 */
int32_t AES_Init_Ex(stc_aes_ctx_t *pCtx, uint8_t u8Mode, uint8_t u8Dir,
                    const uint8_t *pu8Key, uint8_t u8KeySize, const uint8_t *pu8Iv);

/**
 * @brief  Append data to the AES calculation (can be called multiple times).
 *         ECB/CBC: output only advances on full 16-byte blocks, the remaining
 *         bytes are buffered. Decryption holds back the last block until Final
 *         so that PKCS#7 padding can be verified.
 *         CTR: consumes any length and outputs exactly the same number of bytes.
 * @param  [in,out] pCtx        Pointer to the AES context structure.
 * @param  [in]     pu8In       Pointer to the input data buffer.
 * @param  [in]     u32InLen    Length of the input data in bytes.
 * @param  [out]    pu8Out      Pointer to the output buffer.
 * @param  [out]    pu32OutLen  Number of bytes written to pu8Out.
 * @retval LL_OK on success, other values indicate error codes.
 */
int32_t AES_Update_Ex(stc_aes_ctx_t *pCtx, const uint8_t *pu8In, uint32_t u32InLen,
                      uint8_t *pu8Out, uint32_t *pu32OutLen);

/**
 * @brief  Finalize the AES calculation.
 *         ECB/CBC encryption: PKCS#7 pads the last block (1..16 bytes).
 *         ECB/CBC decryption: decrypts the held block, verifies and strips the
 *         PKCS#7 padding.
 *         CTR: no padding, nothing is written.
 *         On success all sensitive material in the context is cleared.
 * @param  [in,out] pCtx        Pointer to the AES context structure.
 * @param  [out]    pu8Out      Pointer to the output buffer.
 * @param  [out]    pu32OutLen  Number of bytes written to pu8Out.
 * @retval LL_OK on success, other values indicate error codes.
 */
int32_t AES_Final_Ex(stc_aes_ctx_t *pCtx, uint8_t *pu8Out, uint32_t *pu32OutLen);

#ifdef __cplusplus
}
#endif

#endif /* __HC32_LL_AES_EX_H__ */
