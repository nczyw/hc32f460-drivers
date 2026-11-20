/**
 * @file  hc32_ll_hash_ex.c
 * @brief Incremental SHA-256 / HMAC-SHA256 built on the HC32F460 HASH engine.
 *
 *        HC32F460 HASH only exposes a SHA-256 engine: CR carries just START
 *        and FST_GRP, there is no HMAC mode, key-length mode, completion flag
 *        or interrupt. Therefore:
 *          - message padding (0x80, zeros, 64-bit bit length) is assembled in
 *            software;
 *          - HMAC is executed as two hardware SHA-256 passes:
 *                inner = SHA256((k0 ^ ipad) || msg)
 *                tag   = SHA256((k0 ^ opad) || inner)
 *        All hashing work runs in hardware, the CPU only does the key padding,
 *        XOR and the 64-byte block assembly.
 */

#include "hc32_ll_hash_ex.h"
#include "hc32_ll_utility.h"

#define HASH_GROUP_SIZE             (64U)
#define HASH_GROUP_SIZE_WORD        (HASH_GROUP_SIZE / 4U)
#define HASH_LAST_GROUP_SIZE_MAX    (56U)
#define HASH_TIMEOUT                (6000U)
#define HASH_MSG_DIGEST_SIZE        (32U)
#define HASH_MSG_DIGEST_SIZE_WORD   (HASH_MSG_DIGEST_SIZE / 4U)
#define HASH_KEY_SIZE               (64U)

#define IPAD_CONST                  (0x36U)
#define OPAD_CONST                  (0x5CU)

static int32_t HASH_WaitStart(void);
static void HASH_WriteDataGroup(const uint8_t *pu8Data);
static void HASH_ReadDigest(uint8_t *pu8Digest);
static void HASH_MemSet(uint8_t *pu8Dest, uint8_t u8Value, uint32_t u32Len);
static void HASH_MemCopy(uint8_t *pu8Dest, const uint8_t *pu8Src, uint32_t u32Len);
static void HASH_PutBitLength(uint8_t *pu8Dst, uint64_t u64BitLen);
static int32_t HASH_StartGroup(uint8_t u8First);
static int32_t HASH_FeedBlock(stc_hash_ctx_t *pCtx, const uint8_t *pu8Block);
static int32_t HASH_ProcessBuffer(stc_hash_ctx_t *pCtx, uint8_t u8Last);
static int32_t HASH_UpdateCore(stc_hash_ctx_t *pCtx, const uint8_t *pu8Data, uint32_t u32Len);

/**
 * @brief  Wait for the HASH operation to complete by polling the START flag.
 * @retval int32_t   LL_OK on success, LL_ERR_TIMEOUT if hardware timeout.
 */
static int32_t HASH_WaitStart(void)
{
    uint32_t u32TimeOut = HASH_TIMEOUT;

    while (READ_REG32_BIT(CM_HASH->CR, HASH_CR_START) != 0UL) {
        if (--u32TimeOut == 0UL) {
            return LL_ERR_TIMEOUT;
        }
    }
    return LL_OK;
}

/**
 * @brief  Write one 64-byte block to DR15..DR0 (most significant word first).
 *         Bytes are assembled explicitly instead of casting the input to a
 *         uint32_t pointer, so unaligned buffers and strict-aliasing rules are
 *         both handled safely.
 * @param  [in] pu8Data    Pointer to the 64-byte data block.
 * @retval None
 */
static void HASH_WriteDataGroup(const uint8_t *pu8Data)
{
    uint8_t i;
    __IO uint32_t *regDR = &CM_HASH->DR15;

    for (i = 0U; i < HASH_GROUP_SIZE_WORD; i++) {
        uint32_t u32Index = (uint32_t)i * 4U;

        regDR[i] = ((uint32_t)pu8Data[u32Index] << 24U) |
                   ((uint32_t)pu8Data[u32Index + 1U] << 16U) |
                   ((uint32_t)pu8Data[u32Index + 2U] << 8U) |
                   ((uint32_t)pu8Data[u32Index + 3U]);
    }
}

/**
 * @brief  Read the 32-byte message digest from HR7..HR0.
 * @param  [out] pu8Digest    Pointer to the 32-byte output buffer.
 * @retval None
 */
static void HASH_ReadDigest(uint8_t *pu8Digest)
{
    uint8_t i;
    __IO uint32_t *regHR = &CM_HASH->HR7;

    for (i = 0U; i < HASH_MSG_DIGEST_SIZE_WORD; i++) {
        uint32_t u32Value = __REV(regHR[i]);

        HASH_MemCopy(&pu8Digest[i * 4U], (const uint8_t *)&u32Value, 4U);
    }
}

/**
 * @brief  Fill a memory area with a constant byte value.
 */
static void HASH_MemSet(uint8_t *pu8Dest, uint8_t u8Value, uint32_t u32Len)
{
    while (u32Len-- != 0U) {
        *pu8Dest++ = u8Value;
    }
}

/**
 * @brief  Copy a memory area from source to destination (no overlap).
 */
static void HASH_MemCopy(uint8_t *pu8Dest, const uint8_t *pu8Src, uint32_t u32Len)
{
    while (u32Len-- != 0U) {
        *pu8Dest++ = *pu8Src++;
    }
}

/**
 * @brief  Store a 64-bit bit length in big-endian order (SHA-256 tail field).
 */
static void HASH_PutBitLength(uint8_t *pu8Dst, uint64_t u64BitLen)
{
    uint8_t i;

    for (i = 0U; i < 8U; i++) {
        pu8Dst[i] = (uint8_t)(u64BitLen >> ((7U - i) * 8U));
    }
}

/**
 * @brief  Write one group and start the SHA-256 engine.
 *         FST_GRP is set for the first group (reloads the SHA-256 IV) and
 *         cleared afterwards, so consecutive groups continue the same digest.
 * @param  [in] u8First    Non-zero for the first group of a new digest.
 * @retval int32_t         LL_OK on success, LL_ERR_TIMEOUT on hardware timeout.
 */
static int32_t HASH_StartGroup(uint8_t u8First)
{
    /* Bit-band writes avoid read-modify-write coupling on CR. */
    WRITE_REG32(bCM_HASH->CR_b.FST_GRP, (u8First != 0U) ? 1UL : 0UL);
    WRITE_REG32(bCM_HASH->CR_b.START, 1UL);

    return HASH_WaitStart();
}

/**
 * @brief  Feed one full 64-byte block into the running digest.
 */
static int32_t HASH_FeedBlock(stc_hash_ctx_t *pCtx, const uint8_t *pu8Block)
{
    int32_t i32Ret;

    HASH_WriteDataGroup(pu8Block);
    i32Ret = HASH_StartGroup((pCtx->started == 0U) ? 1U : 0U);
    if (i32Ret == LL_OK) {
        pCtx->started = 1U;
    }

    return i32Ret;
}

/**
 * @brief  Process the context buffer: either flush a full block, or apply the
 *         SHA-256 padding and finish the current digest.
 * @param  [in,out] pCtx     HASH context.
 * @param  [in]     u8Last   Non-zero to padding and finish.
 * @retval int32_t           LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
static int32_t HASH_ProcessBuffer(stc_hash_ctx_t *pCtx, uint8_t u8Last)
{
    uint8_t u8FillBuffer[HASH_GROUP_SIZE];
    uint32_t u32Len = pCtx->buffer_len;
    uint64_t u64BitLen;
    int32_t i32Ret;

    if (u8Last == 0U) {
        if (u32Len == 0U) {
            return LL_OK;
        }
        if (u32Len != HASH_GROUP_SIZE) {
            return LL_ERR_INVD_PARAM;
        }

        i32Ret = HASH_FeedBlock(pCtx, pCtx->buffer);
        if (i32Ret != LL_OK) {
            return i32Ret;
        }
        pCtx->buffer_len = 0U;
        return LL_OK;
    }

    /* Last block: 0x80, zero padding, then the 64-bit message bit length. */
    HASH_MemSet(u8FillBuffer, 0U, HASH_GROUP_SIZE);
    if (u32Len > 0U) {
        HASH_MemCopy(u8FillBuffer, pCtx->buffer, u32Len);
    }
    u8FillBuffer[u32Len] = 0x80U;

    u64BitLen = pCtx->total_len << 3U;

    if (u32Len < HASH_LAST_GROUP_SIZE_MAX) {
        HASH_PutBitLength(&u8FillBuffer[HASH_LAST_GROUP_SIZE_MAX], u64BitLen);

        i32Ret = HASH_FeedBlock(pCtx, u8FillBuffer);
        if (i32Ret != LL_OK) {
            return i32Ret;
        }
    } else {
        /* Not enough room for the length field: one more full block. */
        i32Ret = HASH_FeedBlock(pCtx, u8FillBuffer);
        if (i32Ret != LL_OK) {
            return i32Ret;
        }

        HASH_MemSet(u8FillBuffer, 0U, HASH_GROUP_SIZE);
        HASH_PutBitLength(&u8FillBuffer[HASH_LAST_GROUP_SIZE_MAX], u64BitLen);

        i32Ret = HASH_FeedBlock(pCtx, u8FillBuffer);
        if (i32Ret != LL_OK) {
            return i32Ret;
        }
    }

    pCtx->buffer_len = 0U;
    pCtx->finished = 1U;

    return LL_OK;
}

/**
 * @brief  Append data to a running SHA-256 digest.
 */
static int32_t HASH_UpdateCore(stc_hash_ctx_t *pCtx, const uint8_t *pu8Data, uint32_t u32Len)
{
    uint32_t u32Offset = 0U;
    int32_t i32Ret;

    while (u32Offset < u32Len) {
        uint32_t u32Space = HASH_GROUP_SIZE - pCtx->buffer_len;
        uint32_t u32Copy = ((u32Len - u32Offset) < u32Space) ? (u32Len - u32Offset) : u32Space;

        HASH_MemCopy(&pCtx->buffer[pCtx->buffer_len], &pu8Data[u32Offset], u32Copy);
        pCtx->buffer_len += u32Copy;
        u32Offset += u32Copy;

        if (pCtx->buffer_len == HASH_GROUP_SIZE) {
            i32Ret = HASH_ProcessBuffer(pCtx, 0U);
            if (i32Ret != LL_OK) {
                return i32Ret;
            }
        }
    }

    return LL_OK;
}

/**
 * @brief  Initialize the HASH context for incremental SHA-256 calculation.
 * @param  [out] pCtx     Pointer to the HASH context structure.
 * @retval int32_t        LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HASH_Init_Ex(stc_hash_ctx_t *pCtx)
{
    if (pCtx == NULL) {
        return LL_ERR_INVD_PARAM;
    }

    (void)HASH_DeInit();

    pCtx->buffer_len = 0U;
    pCtx->total_len  = 0U;
    pCtx->started    = 0U;
    pCtx->finished   = 0U;
    HASH_MemSet(pCtx->buffer, 0U, HASH_GROUP_SIZE);

    return HASH_WaitStart();
}

/**
 * @brief  Append data to the incremental SHA-256 calculation.
 * @param  [in,out] pCtx    Pointer to the HASH context structure.
 * @param  [in]     pData   Pointer to the input data buffer.
 * @param  [in]     u32Len  Length of the input data in bytes.
 * @retval int32_t          LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HASH_Update_Ex(stc_hash_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len)
{
    if ((pCtx == NULL) || (pData == NULL) || (u32Len == 0U) || (pCtx->finished != 0U)) {
        return LL_ERR_INVD_PARAM;
    }

    pCtx->total_len += u32Len;

    return HASH_UpdateCore(pCtx, pData, u32Len);
}

/**
 * @brief  Finalize the incremental SHA-256 calculation and read the digest.
 * @param  [in,out] pCtx          Pointer to the HASH context structure.
 * @param  [out]    pu8MsgDigest  Pointer to the 32-byte digest buffer.
 * @retval int32_t                LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HASH_Final_Ex(stc_hash_ctx_t *pCtx, uint8_t *pu8MsgDigest)
{
    int32_t i32Ret;

    if ((pCtx == NULL) || (pu8MsgDigest == NULL) || (pCtx->finished != 0U)) {
        return LL_ERR_INVD_PARAM;
    }

    i32Ret = HASH_ProcessBuffer(pCtx, 1U);
    if (i32Ret == LL_OK) {
        HASH_ReadDigest(pu8MsgDigest);
    }

    return i32Ret;
}

/**
 * @brief  Initialize the HMAC context and hash the inner key block.
 *         k0 = key (zero padded), or SHA256(key) (zero padded) when the key is
 *         longer than 64 bytes. (k0 ^ ipad) is fed as the first hardware group
 *         of the inner digest, so HMAC_Update_Ex() only has to feed messages.
 * @param  [out] pCtx       Pointer to the HMAC context structure.
 * @param  [in]  pKey       Pointer to the secret key buffer.
 * @param  [in]  u32KeyLen  Length of the secret key in bytes.
 * @retval int32_t          LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HMAC_Init_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pKey, uint32_t u32KeyLen)
{
    uint8_t u8PadBlock[HASH_GROUP_SIZE];
    uint32_t i;
    int32_t i32Ret;

    if ((pCtx == NULL) || (pKey == NULL) || (u32KeyLen == 0U)) {
        return LL_ERR_INVD_PARAM;
    }

    HASH_MemSet(pCtx->k0, 0U, HASH_KEY_SIZE);

    if (u32KeyLen > HASH_KEY_SIZE) {
        stc_hash_ctx_t stcKeyCtx;

        i32Ret = HASH_Init_Ex(&stcKeyCtx);
        if (i32Ret == LL_OK) {
            i32Ret = HASH_Update_Ex(&stcKeyCtx, pKey, u32KeyLen);
        }
        if (i32Ret == LL_OK) {
            i32Ret = HASH_Final_Ex(&stcKeyCtx, pCtx->k0);
        }
        if (i32Ret != LL_OK) {
            return i32Ret;
        }
    } else {
        HASH_MemCopy(pCtx->k0, pKey, u32KeyLen);
    }

    /* Restart the engine and feed (k0 ^ ipad) as the first inner group. */
    (void)HASH_DeInit();

    for (i = 0U; i < HASH_GROUP_SIZE; i++) {
        u8PadBlock[i] = pCtx->k0[i] ^ IPAD_CONST;
    }

    pCtx->inner_ctx.buffer_len = 0U;
    pCtx->inner_ctx.total_len  = HASH_GROUP_SIZE;
    pCtx->inner_ctx.started    = 0U;
    pCtx->inner_ctx.finished   = 0U;
    HASH_MemSet(pCtx->inner_ctx.buffer, 0U, HASH_GROUP_SIZE);

    pCtx->outer_ctx.buffer_len = 0U;
    pCtx->outer_ctx.total_len  = 0U;
    pCtx->outer_ctx.started    = 0U;
    pCtx->outer_ctx.finished   = 0U;
    HASH_MemSet(pCtx->outer_ctx.buffer, 0U, HASH_GROUP_SIZE);

    i32Ret = HASH_FeedBlock(&pCtx->inner_ctx, u8PadBlock);
    if (i32Ret != LL_OK) {
        return i32Ret;
    }

    pCtx->state = 1U;

    return LL_OK;
}

/**
 * @brief  Append message data to the HMAC inner digest.
 * @param  [in,out] pCtx    Pointer to the HMAC context structure.
 * @param  [in]     pData   Pointer to the message data buffer.
 * @param  [in]     u32Len  Length of the message data in bytes.
 * @retval int32_t          LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HMAC_Update_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len)
{
    if ((pCtx == NULL) || (pCtx->state != 1U)) {
        return LL_ERR_INVD_PARAM;
    }
    if ((pData == NULL) && (u32Len != 0U)) {
        return LL_ERR_INVD_PARAM;
    }
    if (u32Len == 0U) {
        return LL_OK;
    }

    pCtx->inner_ctx.total_len += u32Len;

    return HASH_UpdateCore(&pCtx->inner_ctx, pData, u32Len);
}

/**
 * @brief  Finalize HMAC: inner digest, then outer hardware SHA-256 pass.
 * @param  [in,out] pCtx          Pointer to the HMAC context structure.
 * @param  [out]    pu8MsgDigest  Pointer to the 32-byte tag buffer.
 * @retval int32_t                LL_OK, LL_ERR_INVD_PARAM or LL_ERR_TIMEOUT.
 */
int32_t HMAC_Final_Ex(stc_hmac_ctx_t *pCtx, uint8_t *pu8MsgDigest)
{
    uint8_t u8PadBlock[HASH_GROUP_SIZE];
    uint8_t u8InnerDigest[HASH_MSG_DIGEST_SIZE];
    uint32_t i;
    int32_t i32Ret;

    if ((pCtx == NULL) || (pu8MsgDigest == NULL) || (pCtx->state != 1U)) {
        return LL_ERR_INVD_PARAM;
    }

    /* inner = SHA256((k0 ^ ipad) || msg) */
    i32Ret = HASH_ProcessBuffer(&pCtx->inner_ctx, 1U);
    if (i32Ret != LL_OK) {
        return i32Ret;
    }
    HASH_ReadDigest(u8InnerDigest);

    /* tag = SHA256((k0 ^ opad) || inner) */
    for (i = 0U; i < HASH_GROUP_SIZE; i++) {
        u8PadBlock[i] = pCtx->k0[i] ^ OPAD_CONST;
    }

    pCtx->outer_ctx.buffer_len = 0U;
    pCtx->outer_ctx.total_len  = HASH_GROUP_SIZE;
    pCtx->outer_ctx.started    = 0U;
    pCtx->outer_ctx.finished   = 0U;

    i32Ret = HASH_FeedBlock(&pCtx->outer_ctx, u8PadBlock);
    if (i32Ret != LL_OK) {
        return i32Ret;
    }

    HASH_MemCopy(pCtx->outer_ctx.buffer, u8InnerDigest, HASH_MSG_DIGEST_SIZE);
    pCtx->outer_ctx.buffer_len = HASH_MSG_DIGEST_SIZE;
    pCtx->outer_ctx.total_len += HASH_MSG_DIGEST_SIZE;

    i32Ret = HASH_ProcessBuffer(&pCtx->outer_ctx, 1U);
    if (i32Ret != LL_OK) {
        return i32Ret;
    }

    HASH_ReadDigest(pu8MsgDigest);
    pCtx->state = 2U;

    return LL_OK;
}
