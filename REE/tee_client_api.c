#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>


/*real libteec symbols from tee_client_api_wrapper.h. */
#define TITANSSL_WRAPPER_INTERNAL 1
#include "tee_client_api_wrapper.h"

/* Use the real OP-TEE Client API header  */
#include <tee_client_api.h>

#include "titanssl_common.h"  /* titanssl_parameters_t, TITANSSL_CMD_* */
#include "uuid_ta.h"          /* SHA_TA_UUID, AES_TA_UUID */

/* --------------------------- Debug macro --------------------------- */
#define DBG_PRINT(...) do {                                      \
    fprintf(stderr, "[DEBUG] %s:%d: ", __func__, __LINE__);       \
    fprintf(stderr, __VA_ARGS__);                                 \
    fputc('\n', stderr);                                          \
} while (0)



/* -------------------- Global real context/sessions -------------------- */
static TEEC_Context  real_ctx;
static TEEC_Session  real_sess_sha; 
static TEEC_Session  real_sess_aes;  
static int           initialized = 0;

/* ---------------- Tiny token overlay for engine's 8-byte md_data ----------------
 * The engine allocates 8 bytes (its own TEEC_Session). We never touch the
 * real libteec TEEC_Session here; we only treat the incoming pointer as this
 * tiny struct to carry a token.
 */
struct tiny_sess {
    uint32_t token;
    uint32_t reserved;
};
#define TINY_TOKEN 0x54534553u  // ASCII: 'T' 'S' 'E' 'S'  => "TSES"
#define TINY(p) ((struct tiny_sess*)(void*)(p))

/* ---------------- Legacy outer operation layout from engine ---------------- */
struct legacy_operation {
    uint32_t started;
    uint32_t paramTypes;
    void    *data_in_addr;
    void    *data_out_addr;
    size_t   data_size;
    TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

/* =========================== Zero-copy helpers =========================== */

/* Threshold for taking the zero-copy path (bytes) */
#ifndef TITANSSL_ZC_THRESHOLD
#define TITANSSL_ZC_THRESHOLD 1
#endif

/*
 * Maximum data exposed to the TA in one invocation.
 *
 * SHA:
 *   6.5 MiB was observed working, 7 MiB failed.
 *   Use 6 MiB.
 *
 * AES:
 *   AES has both input and output memrefs.
 *   Start conservatively at 3 MiB and validate correctness/performance.
 */
#ifndef TITANSSL_SHA_MAX_INVOKE
#define TITANSSL_SHA_MAX_INVOKE (6U * 1024U * 1024U)
#endif

#ifndef TITANSSL_AES_MAX_INVOKE
#define TITANSSL_AES_MAX_INVOKE (3U * 1024U * 1024U)
#endif

/*
 * Maximum SHA input presented to the TA in one invocation.
 *
 * Measured platform behaviour:
 *   6.5 MiB succeeds
 *   7.0 MiB fails with TEE_ERROR_OUT_OF_MEMORY
 *
 * Use 6 MiB to keep a safety margin.
 */
#ifndef TITANSSL_SHA_MAX_INVOKE
#define TITANSSL_SHA_MAX_INVOKE (6U * 1024U * 1024U)
#endif

static inline bool use_zerocopy(size_t n) {
    return n >= TITANSSL_ZC_THRESHOLD;
}


static size_t titan_pagesz(void) {
    static size_t ps = 0;
    if (!ps) ps = (size_t)sysconf(_SC_PAGESIZE);
    return ps ? ps : 4096;
}

static inline uintptr_t align_down_u(uintptr_t x, size_t a) {
    return x & ~((uintptr_t)a - 1);
}
static inline size_t align_up_s(size_t x, size_t a) {
    return (x + a - 1) & ~(a - 1);
}

/* Page-based cache: register a stable page-aligned base and reuse with offsets */
typedef struct {
    void *base;              /* page-aligned base pointer registered */
    size_t cap;              /* registered capacity in bytes */
    TEEC_SharedMemory shm;   /* underlying SHM handle */
    bool valid;
} zc_page_cache_t;

/* Replace AES pointer-equality caches with page-aligned caches */
#define AES_PG_CACHE_N 2
static zc_page_cache_t aes_in_pg[AES_PG_CACHE_N]  = {0};
static zc_page_cache_t aes_out_pg[AES_PG_CACHE_N] = {0};
static unsigned aes_in_rr  = 0;
static unsigned aes_out_rr = 0;




/* ---------- AES ZC stats & caches (mirrors SHA style) ---------- */

static size_t aes_zc_calls_in  = 0, aes_tmp_calls_in  = 0;
static size_t aes_zc_calls_out = 0, aes_tmp_calls_out = 0;
static size_t aes_reg_calls    = 0, aes_rel_calls     = 0;

// Page-based shared memory registration helper with a multi-entry cache.
// The goal of this function is to avoid registering and releasing shared
// memory on every AES call by reusing already-registered memory pages.
//
// Instead of tracking exact buffer pointers, we track memory *pages*.
// If a buffer moves inside the same page, we reuse the same shared memory.
// This dramatically reduces TEEC_RegisterSharedMemory / Release calls.
static TEEC_Result ensure_pg_shm_multi(
    TEEC_Context *ctx,              // Active OP-TEE context (connection to TEE)
    zc_page_cache_t cache[],        // Array of cached registered pages
    unsigned n,                     // Number of cache entries
    unsigned *rr_idx,               // Round-robin index for eviction
    void *ptr, size_t len,           // Original buffer pointer and length
    uint32_t flags,                 // TEEC_MEM_INPUT or TEEC_MEM_OUTPUT
    size_t *out_off)                // Offset of ptr inside the page
{
    // Get system page size (typically 4096 bytes)
    size_t ps = titan_pagesz();

    // Convert pointer to integer for address calculations
    uintptr_t p = (uintptr_t)ptr;

    // Align pointer down to the start of its memory page
    // Example: ptr=0x88d1c8 → base_u=0x88d000
    uintptr_t base_u = align_down_u(p, ps);

    // Calculate offset of ptr inside the page
    // Example: 0x88d1c8 - 0x88d000 = 456 bytes
    size_t off = (size_t)(p - base_u);

    // Compute how many bytes must be covered from page start
    // We must include offset + buffer length
    size_t need = off + len;

    // Round up to full page size (OP-TEE works better with page-aligned sizes)
    size_t cap  = align_up_s(need, ps);

    // Return offset to caller so it can use TEEC_MEMREF_PARTIAL
    if (out_off) *out_off = off;

    // ------------------------------------------------------------
    // STEP 1: Try to reuse an already-registered page
    // ------------------------------------------------------------
    for (unsigned i = 0; i < n; i++) {
        // If cache entry is valid AND
        // page base matches AND
        // registered size is large enough
        if (cache[i].valid &&
            cache[i].base == (void*)base_u &&
            cache[i].cap >= cap) {

            // Page already registered → no new register needed
            return TEEC_SUCCESS;
        }
    }

    // ------------------------------------------------------------
    // STEP 2: Select a cache entry to use
    // ------------------------------------------------------------

    // Prefer an unused cache entry
    unsigned v = n; // invalid marker
    for (unsigned i = 0; i < n; i++) {
        if (!cache[i].valid) {
            v = i;
            break;
        }
    }

    // If all entries are in use, evict one using round-robin policy
    if (v == n) {
        v = (*rr_idx)++ % n;
    }

    // ------------------------------------------------------------
    // STEP 3: Release old shared memory if needed
    // ------------------------------------------------------------
    if (cache[v].valid) {
        // This page was previously registered → release it
        DBG_PRINT("AES ensure_pg_shm: releasing old SHM base=%p cap=%zu",
                  cache[v].base, cache[v].cap);

        TEEC_ReleaseSharedMemory(&cache[v].shm);
        aes_rel_calls++;

        cache[v].valid = false;
        cache[v].base  = NULL;
        cache[v].cap   = 0;
    }

    // ------------------------------------------------------------
    // STEP 4: Register the new page as shared memory
    // ------------------------------------------------------------

    // Clear shared memory structure
    memset(&cache[v].shm, 0, sizeof(cache[v].shm));

    // Register the page-aligned base, not the original pointer
    cache[v].shm.buffer = (void*)base_u;
    cache[v].shm.size   = cap;
    cache[v].shm.flags  = flags;

    // Perform OP-TEE shared memory registration
    TEEC_Result r = TEEC_RegisterSharedMemory(ctx, &cache[v].shm);
    aes_reg_calls++;

    DBG_PRINT("AES ensure_pg_shm: base=%p cap=%zu (ptr=%p len=%zu off=%zu) -> 0x%x",
              (void*)base_u, cap, ptr, len, off, r);

    // If registration failed, abort
    if (r != TEEC_SUCCESS)
        return r;

    // ------------------------------------------------------------
    // STEP 5: Store registration info in cache for reuse
    // ------------------------------------------------------------
    cache[v].base  = (void*)base_u;  // Page base address
    cache[v].cap   = cap;            // Registered capacity
    cache[v].valid = true;           // Mark cache entry valid

    return TEEC_SUCCESS;
}


/* Per-buffer cache (pointer + capacity + SHM handle) */
typedef struct {
    void *ptr;                 /* registered pointer        */
    size_t size;               /* capacity registered for   */
    TEEC_SharedMemory shm;     /* SHM handle                */
    bool valid;                /* cache valid flag          */
} zc_cache_t;

/* ---------- SHA ZC (input stream + final tail) stats ---------- */
static size_t sha_zc_updates      = 0;
static size_t sha_tmp_updates     = 0;
static size_t sha_zc_final_tails  = 0;
static size_t sha_tmp_final_tails = 0;
static size_t sha_reg_calls       = 0;
static size_t sha_rel_calls       = 0;

static zc_cache_t sha_in_zc = {0}; /* cached input SHM across UPDATEs */


/* Separate caches for IN and OUT buffers so we can reuse both sides */
static zc_cache_t aes_in_zc  = {0};
static zc_cache_t aes_out_zc = {0};

/* -------------------- Control-block finder (robust) -------------------- */
/* Prefer index 2, then 0,1,3; verify type/size and p->cmd == expected_cmd. */
// locate the titanssl_parameters_t control block in the operation parameters.
static titanssl_parameters_t*
find_ctrlblock_for_cmd(struct legacy_operation *lop, uint32_t expected_cmd, int *out_idx)
{
    static const int order[TEEC_CONFIG_PAYLOAD_REF_COUNT] = { 2, 0, 1, 3 };

    for (int k = 0; k < TEEC_CONFIG_PAYLOAD_REF_COUNT; ++k) {
        int i = order[k];
        uint32_t t = TEEC_PARAM_TYPE_GET(lop->paramTypes, i);
        if (t != TEEC_MEMREF_TEMP_INPUT)
            continue;

        void   *buf = lop->params[i].tmpref.buffer;
        size_t  sz  = lop->params[i].tmpref.size;
        if (!buf || sz < sizeof(titanssl_parameters_t))
            continue;

        titanssl_parameters_t *p = (titanssl_parameters_t*)buf;
        if ((unsigned long)expected_cmd != p->cmd)
            continue;

        if (out_idx) *out_idx = i;
        return p;
    }
    return NULL;
}

/* ================================ API ================================ */

TEEC_Result TitanSSL_TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    
    (void)name;



    if (!initialized) {
        TEEC_Result res;

        DBG_PRINT("Calling real TEEC_InitializeContext");
        res = TEEC_InitializeContext(NULL, &real_ctx);
        DBG_PRINT("TEEC_InitializeContext -> 0x%x", res);
        if (res != TEEC_SUCCESS)
            return res;

        uint32_t origin = 0;

        DBG_PRINT("Opening real TEEC session to SHA TA");
        res = TEEC_OpenSession(&real_ctx, &real_sess_sha, &SHA_TA_UUID,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
        DBG_PRINT("TEEC_OpenSession(SHA) -> 0x%x (origin=%u)", res, origin);
        if (res != TEEC_SUCCESS) {
            TEEC_FinalizeContext(&real_ctx);
            return res;
        }

        DBG_PRINT("Opening real TEEC session to AES TA");
        res = TEEC_OpenSession(&real_ctx, &real_sess_aes, &AES_TA_UUID,
                               TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
        DBG_PRINT("TEEC_OpenSession(AES) -> 0x%x (origin=%u)", res, origin);
        if (res != TEEC_SUCCESS) {
            TEEC_CloseSession(&real_sess_sha);
            TEEC_FinalizeContext(&real_ctx);
            return res;
        }

        initialized = 1;
    }

    /* Engine uses this as a dummy indicator */
    context->imp.fd = 1;
    DBG_PRINT("Exit");
    return TEEC_SUCCESS;
}

void TitanSSL_TEEC_FinalizeContext(TEEC_Context *context)
{
    (void)context;
    DBG_PRINT("Enter");

    /* Release any lingering SHA/AES cached SHM (defensive) */
    if (sha_in_zc.valid)   { TEEC_ReleaseSharedMemory(&sha_in_zc.shm);   sha_rel_calls++; sha_in_zc.valid   = false; sha_in_zc.ptr   = NULL; sha_in_zc.size   = 0; }
    if (aes_in_zc.valid)   { TEEC_ReleaseSharedMemory(&aes_in_zc.shm);   aes_rel_calls++; aes_in_zc.valid   = false; aes_in_zc.ptr   = NULL; aes_in_zc.size   = 0; }
    if (aes_out_zc.valid)  { TEEC_ReleaseSharedMemory(&aes_out_zc.shm);  aes_rel_calls++; aes_out_zc.valid  = false; aes_out_zc.ptr  = NULL; aes_out_zc.size  = 0; }

    if (initialized) {
        DBG_PRINT("Closing real sessions + finalizing context");
        TEEC_CloseSession(&real_sess_aes);
        TEEC_CloseSession(&real_sess_sha);
        TEEC_FinalizeContext(&real_ctx);
        initialized = 0;

        DBG_PRINT("SHA ZC stats: update_zc=%zu update_tmp=%zu final_tail_zc=%zu final_tail_tmp=%zu reg=%zu rel=%zu",
                  sha_zc_updates, sha_tmp_updates, sha_zc_final_tails, sha_tmp_final_tails,
                  sha_reg_calls, sha_rel_calls);

        DBG_PRINT("AES ZC stats: in_zc=%zu in_tmp=%zu out_zc=%zu out_tmp=%zu reg=%zu rel=%zu",
                  aes_zc_calls_in, aes_tmp_calls_in, aes_zc_calls_out, aes_tmp_calls_out,
                  aes_reg_calls, aes_rel_calls);
    }
    DBG_PRINT("Exit");
}

TEEC_Result TitanSSL_TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
                                      const TEEC_UUID *destination,
                                      uint32_t connectionMethod,
                                      const void *connectionData,
                                      TEEC_Operation *operation,
                                      uint32_t *returnOrigin)
{
    (void)context; (void)destination; (void)connectionMethod; (void)connectionData;
    (void)operation;
    DBG_PRINT("Enter");
    if (!session) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        DBG_PRINT("Bad parameters");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    /* Stamp our tiny token into the 8-byte area the engine gave us */
    TINY(session)->token = TINY_TOKEN;
    DBG_PRINT("Exit (tiny token=0x%08x)", TINY(session)->token);
    return TEEC_SUCCESS;
}

void TitanSSL_TEEC_CloseSession(TEEC_Session *session)
{
    (void)session;
    DBG_PRINT("Enter/Exit (no real close)");
}

TEEC_Result TitanSSL_TEEC_InvokeCommand(TEEC_Session *session,
                                        uint32_t commandID,
                                        TEEC_Operation *operation,
                                        uint32_t *returnOrigin)
{
    DBG_PRINT("Enter CMD=%u", commandID);

    if (!session || TINY(session)->token != TINY_TOKEN) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_STATE;
    }

    /* Route to correct TA session */
    TEEC_Session *target = NULL;
    switch (commandID) {
    case TITANSSL_CMD_SHA256_INIT:
    case TITANSSL_CMD_SHA256_UPDATE:
    case TITANSSL_CMD_SHA256_FINAL:
        target = &real_sess_sha; break;

    case TITANSSL_CMD_AES_INIT:
    case TITANSSL_CMD_AES_DOCIPHER:
    case TITANSSL_CMD_AES_CLEANUP:
        target = &real_sess_aes; break;

    default:
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_NOT_SUPPORTED;
    }

    /* ---------------------------- SHA path ---------------------------- */

    if (commandID == TITANSSL_CMD_SHA256_INIT) {
        uint32_t origin = 0;
        TEEC_Operation empty = (TEEC_Operation){0};
        empty.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

        DBG_PRINT("SHA INIT: trying empty op (NONE x4)");
        TEEC_Result r = TEEC_InvokeCommand(target, commandID, &empty, &origin);
        if (r == TEEC_ERROR_BAD_PARAMETERS && origin == TEEC_ORIGIN_API) {
            DBG_PRINT("SHA INIT: BAD_PARAMETERS; retry with op=NULL");
            r = TEEC_InvokeCommand(target, commandID, NULL, &origin);
        }
        if (returnOrigin) *returnOrigin = origin;
        DBG_PRINT("SHA INIT: result=0x%x (origin=%u)", r, origin);
        return r;
    }

    if (!operation) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    struct legacy_operation *lop = (struct legacy_operation *)(void *)operation;

    int ctrl_idx = -1;
    titanssl_parameters_t *p = find_ctrlblock_for_cmd(lop, commandID, &ctrl_idx);
    if (!p) {
        DBG_PRINT("Control block not found");
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    uint32_t origin = 0;
    TEEC_Result r;
    TEEC_Operation op2; memset(&op2, 0, sizeof(op2));

    if (commandID == TITANSSL_CMD_SHA256_UPDATE) {

        if (!p->input_address || p->input_size == 0) {
            if (returnOrigin)
                *returnOrigin = TEEC_ORIGIN_API;
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        uint8_t *in = (uint8_t *)(uintptr_t)p->input_address;
        size_t len  = (size_t)p->input_size;

        const size_t max_chunk =
            (size_t)TITANSSL_SHA_MAX_INVOKE;

        /*
         * ========================================================
         * SHA ZC
         * ========================================================
         *
         * Register only one bounded window at a time.
         *
         * The page-aligned base allows PARTIAL_INPUT to point at
         * the exact OpenSSL data without copying it.
         */
        if (use_zerocopy(len)) {

            size_t offset = 0;
            size_t ps = titan_pagesz();

            while (offset < len) {

                size_t chunk = len - offset;

                if (chunk > max_chunk)
                    chunk = max_chunk;

                uint8_t *chunk_ptr = in + offset;

                uintptr_t ptr_u =
                    (uintptr_t)chunk_ptr;

                uintptr_t base_u =
                    align_down_u(ptr_u, ps);

                size_t shm_off =
                    (size_t)(ptr_u - base_u);

                /*
                 * Start is page aligned.
                 * Do not round the end beyond our actual buffer.
                 */
                size_t shm_len =
                    shm_off + chunk;

                TEEC_SharedMemory shm;
                memset(&shm, 0, sizeof(shm));

                shm.buffer = (void *)base_u;
                shm.size   = shm_len;
                shm.flags  = TEEC_MEM_INPUT;

                r = TEEC_RegisterSharedMemory(
                        &real_ctx,
                        &shm);

                sha_reg_calls++;

                DBG_PRINT(
                    "SHA UPDATE ZC WINDOW REG: "
                    "off=%zu data=%zu shm_off=%zu shm_len=%zu -> 0x%x",
                    offset,
                    chunk,
                    shm_off,
                    shm_len,
                    r);

                if (r != TEEC_SUCCESS) {
                    if (returnOrigin)
                        *returnOrigin = TEEC_ORIGIN_API;
                    return r;
                }

                memset(&op2, 0, sizeof(op2));

                op2.paramTypes =
                    TEEC_PARAM_TYPES(
                        TEEC_MEMREF_PARTIAL_INPUT,
                        TEEC_NONE,
                        TEEC_NONE,
                        TEEC_NONE);

                op2.params[0].memref.parent = &shm;
                op2.params[0].memref.offset = shm_off;
                op2.params[0].memref.size   = chunk;

                r = TEEC_InvokeCommand(
                        target,
                        commandID,
                        &op2,
                        &origin);

                DBG_PRINT(
                    "SHA UPDATE ZC WINDOW INVOKE: "
                    "off=%zu len=%zu/%zu -> 0x%x (origin=%u)",
                    offset,
                    chunk,
                    len,
                    r,
                    origin);

                sha_zc_updates++;

                TEEC_ReleaseSharedMemory(&shm);
                sha_rel_calls++;

                if (r != TEEC_SUCCESS) {
                    if (returnOrigin)
                        *returnOrigin = origin;
                    return r;
                }

                offset += chunk;
            }

            if (returnOrigin)
                *returnOrigin = origin;

            return TEEC_SUCCESS;
        }

        /*
         * ========================================================
         * SHA TEMP / ZX
         * ========================================================
         */
        size_t offset = 0;

        while (offset < len) {

            size_t chunk = len - offset;

            if (chunk > max_chunk)
                chunk = max_chunk;

            memset(&op2, 0, sizeof(op2));

            op2.paramTypes =
                TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_NONE,
                    TEEC_NONE,
                    TEEC_NONE);

            op2.params[0].tmpref.buffer =
                in + offset;

            op2.params[0].tmpref.size =
                chunk;

            r = TEEC_InvokeCommand(
                    target,
                    commandID,
                    &op2,
                    &origin);

            DBG_PRINT(
                "SHA UPDATE TMP CHUNK: "
                "off=%zu len=%zu/%zu -> 0x%x (origin=%u)",
                offset,
                chunk,
                len,
                r,
                origin);

            sha_tmp_updates++;

            if (r != TEEC_SUCCESS) {
                if (returnOrigin)
                    *returnOrigin = origin;
                return r;
            }

            offset += chunk;
        }

        if (returnOrigin)
            *returnOrigin = origin;

        return TEEC_SUCCESS;
    }

    if (commandID == TITANSSL_CMD_SHA256_FINAL) {
        void  *tail   = (void *)(uintptr_t)p->input_address;
        size_t tail_n = (size_t)p->input_size;

        if (!p->output_address) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        void  *outbuf = (void *)(uintptr_t)p->output_address;
        size_t outlen = p->output_size ? (size_t)p->output_size : 32;

        /* Prepare output SHM (digest) */
        TEEC_SharedMemory out_shm = { .size = outlen, .flags = TEEC_MEM_OUTPUT };
        r = TEEC_AllocateSharedMemory(&real_ctx, &out_shm);
        if (r != TEEC_SUCCESS) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            return r;
        }

        /* Default: p0 is MEMREF_INPUT even when 0 bytes; p1 is digest out */
        op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
        op2.params[1].memref.parent = &out_shm;

        if (tail_n == 0) {
            static uint8_t dummy;
            op2.params[0].tmpref.buffer = &dummy;
            op2.params[0].tmpref.size   = 0;

            r = TEEC_InvokeCommand(target, commandID, &op2, &origin);
            DBG_PRINT("SHA FINAL no-tail: 0x%x (origin=%u)", r, origin);
        } else if (use_zerocopy(tail_n)) {
            /* ZC tail (short-lived registration) */
            TEEC_SharedMemory in_shm = { .buffer = tail, .size = tail_n, .flags = TEEC_MEM_INPUT };
            r = TEEC_RegisterSharedMemory(&real_ctx, &in_shm);
            sha_reg_calls++;
            DBG_PRINT("SHA FINAL ZC: Reg IN tail=%p len=%zu -> 0x%x", tail, tail_n, r);
            if (r == TEEC_SUCCESS) {
                op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
                op2.params[0].memref.parent = &in_shm;
                op2.params[0].memref.offset = 0;
                op2.params[0].memref.size   = tail_n;

                r = TEEC_InvokeCommand(target, commandID, &op2, &origin);
                DBG_PRINT("SHA FINAL ZC: Invoke -> 0x%x (origin=%u)", r, origin);

                TEEC_ReleaseSharedMemory(&in_shm);
                sha_rel_calls++;
                sha_zc_final_tails++;
            } else {
                /* Fallback: TEMP tail */
                op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
                op2.params[0].tmpref.buffer = tail;
                op2.params[0].tmpref.size   = tail_n;
                r = TEEC_InvokeCommand(target, commandID, &op2, &origin);
                DBG_PRINT("SHA FINAL TMP-FALLBACK: 0x%x (origin=%u)", r, origin);
                sha_tmp_final_tails++;
            }
        } else {
            /* Small tail: TEMP */
            op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
            op2.params[0].tmpref.buffer = tail;
            op2.params[0].tmpref.size   = tail_n;
            r = TEEC_InvokeCommand(target, commandID, &op2, &origin);
            DBG_PRINT("SHA FINAL TMP: 0x%x (origin=%u)", r, origin);
            sha_tmp_final_tails++;
        }

        /* Copy digest out */
        if (r == TEEC_SUCCESS && out_shm.buffer && outbuf) {
            size_t got = out_shm.size ? out_shm.size : outlen;
            memcpy(outbuf, out_shm.buffer, got);
            p->output_size = (unsigned long)got;
        }

        TEEC_ReleaseSharedMemory(&out_shm);

        /*release UPDATE cache at end of stream */
        if (sha_in_zc.valid) {
            TEEC_ReleaseSharedMemory(&sha_in_zc.shm);
            sha_rel_calls++;
            sha_in_zc.valid = false;
            sha_in_zc.ptr   = NULL;
            sha_in_zc.size  = 0;
        }

        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

    /* ---------------------------- AES path ---------------------------- */
if (commandID == TITANSSL_CMD_AES_INIT) {

    size_t meta_sz = sizeof(titanssl_meta_aes_t);

    if (!p->meta_address || p->meta_size < meta_sz) {
        DBG_PRINT("AES INIT: invalid meta (addr=0x%lx size=%lu need=%zu)",
                  (unsigned long)p->meta_address,
                  (unsigned long)p->meta_size,
                  meta_sz);
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    void *meta_ptr = (void *)(uintptr_t)p->meta_address;

    /* Zero-copy register meta */
    TEEC_SharedMemory meta_shm;
    memset(&meta_shm, 0, sizeof(meta_shm));
    meta_shm.buffer = meta_ptr;
    meta_shm.size   = meta_sz;
    meta_shm.flags  = TEEC_MEM_INPUT;

    TEEC_Result rr = TEEC_RegisterSharedMemory(&real_ctx, &meta_shm);

    DBG_PRINT("AES INIT META REG: ptr=%p size=%zu -> 0x%x",
              meta_ptr, meta_sz, rr);

    if (rr != TEEC_SUCCESS) {
        /* TEMP fallback */
        titanssl_meta_aes_t meta_copy;
        memcpy(&meta_copy, meta_ptr, meta_sz);

        TEEC_Operation op2i;
        memset(&op2i, 0, sizeof(op2i));
        op2i.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                           TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op2i.params[0].tmpref.buffer = &meta_copy;
        op2i.params[0].tmpref.size   = meta_sz;

        uint32_t origin = 0;
        TEEC_Result r = TEEC_InvokeCommand(target, commandID, &op2i, &origin);

        DBG_PRINT("AES INIT TEMP INVOKE: result=0x%x origin=%u",
                  r, origin);

        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

    /* Normal ZC path */
    TEEC_Operation op2i;
    memset(&op2i, 0, sizeof(op2i));
    op2i.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                       TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op2i.params[0].memref.parent = &meta_shm;
    op2i.params[0].memref.offset = 0;
    op2i.params[0].memref.size   = meta_sz;

    uint32_t origin = 0;
    TEEC_Result r = TEEC_InvokeCommand(target, commandID, &op2i, &origin);

    DBG_PRINT("AES INIT ZC INVOKE: result=0x%x origin=%u",
              r, origin);

    TEEC_ReleaseSharedMemory(&meta_shm);

    if (returnOrigin) *returnOrigin = origin;
    return r;
}

    if (commandID == TITANSSL_CMD_AES_DOCIPHER) {

        uint8_t *in_buf  = NULL;
        size_t   in_len  = 0;
        uint8_t *out_buf = NULL;
        size_t   out_len = 0;

        /*
         * Resolve buffers from TitanSSL control block first.
         */
        if (p->input_address &&
            p->input_size &&
            p->output_address) {

            in_buf =
                (uint8_t *)(uintptr_t)p->input_address;

            in_len =
                (size_t)p->input_size;

            out_buf =
                (uint8_t *)(uintptr_t)p->output_address;

            out_len =
                (size_t)(p->output_size ?
                         p->output_size :
                         p->input_size);

            DBG_PRINT(
                "AES DOCIPHER (CB): "
                "in=%p len=%zu out=%p out_len=%zu",
                in_buf, in_len,
                out_buf, out_len);

        } else {

            /*
             * Direct OpenSSL tmpref path.
             */
            uint32_t t0 =
                TEEC_PARAM_TYPE_GET(lop->paramTypes, 0);

            uint32_t t1 =
                TEEC_PARAM_TYPE_GET(lop->paramTypes, 1);

            if (t0 == TEEC_MEMREF_TEMP_INPUT &&
                t1 == TEEC_MEMREF_TEMP_OUTPUT &&
                lop->params[0].tmpref.buffer &&
                lop->params[1].tmpref.buffer &&
                lop->params[0].tmpref.size > 0) {

                in_buf =
                    (uint8_t *)lop->params[0].tmpref.buffer;

                in_len =
                    lop->params[0].tmpref.size;

                out_buf =
                    (uint8_t *)lop->params[1].tmpref.buffer;

                out_len =
                    lop->params[1].tmpref.size;

                DBG_PRINT(
                    "AES DOCIPHER (DIRECT): "
                    "in=%p len=%zu out=%p out_len=%zu",
                    in_buf, in_len,
                    out_buf, out_len);
            }
        }

        if (!in_buf ||
            !out_buf ||
            in_len == 0) {

            if (returnOrigin)
                *returnOrigin = TEEC_ORIGIN_API;

            return TEEC_ERROR_BAD_PARAMETERS;
        }

        /*
         * AES-CBC NOPAD requires complete 16-byte blocks.
         */
        if ((in_len & 0x0F) != 0 ||
            out_len < in_len) {

            DBG_PRINT(
                "AES DOCIPHER: bad lengths "
                "in=%zu out=%zu",
                in_len,
                out_len);

            if (returnOrigin)
                *returnOrigin = TEEC_ORIGIN_API;

            return TEEC_ERROR_BAD_PARAMETERS;
        }

        const size_t max_chunk =
            (size_t)TITANSSL_AES_MAX_INVOKE;

        if (max_chunk == 0 ||
            (max_chunk & 0x0F) != 0) {

            if (returnOrigin)
                *returnOrigin = TEEC_ORIGIN_API;

            return TEEC_ERROR_BAD_PARAMETERS;
        }

        /*
         * ========================================================
         * ZERO-COPY
         * ========================================================
         */
        if (use_zerocopy(in_len)) {

            /*
             * ----------------------------------------------------
             * SMALL / STREAMING ZC
             * ----------------------------------------------------
             *
             * For normal OpenSSL streaming calls (for example
             * repeated 4 KiB buffers), keep the page registrations
             * cached and reuse them.
             *
             * This is the important optimization for openssl enc.
             */
            if (in_len <= max_chunk &&
                in_buf != out_buf) {

                size_t in_off  = 0;
                size_t out_off = 0;

                r = ensure_pg_shm_multi(
                        &real_ctx,
                        aes_in_pg,
                        AES_PG_CACHE_N,
                        &aes_in_rr,
                        in_buf,
                        in_len,
                        TEEC_MEM_INPUT,
                        &in_off);

                if (r != TEEC_SUCCESS) {
                    if (returnOrigin)
                        *returnOrigin = TEEC_ORIGIN_API;

                    return r;
                }

                r = ensure_pg_shm_multi(
                        &real_ctx,
                        aes_out_pg,
                        AES_PG_CACHE_N,
                        &aes_out_rr,
                        out_buf,
                        in_len,
                        TEEC_MEM_OUTPUT,
                        &out_off);

                if (r != TEEC_SUCCESS) {
                    if (returnOrigin)
                        *returnOrigin = TEEC_ORIGIN_API;

                    return r;
                }

                uintptr_t in_base =
                    align_down_u(
                        (uintptr_t)in_buf,
                        titan_pagesz());

                uintptr_t out_base =
                    align_down_u(
                        (uintptr_t)out_buf,
                        titan_pagesz());

                TEEC_SharedMemory *in_parent  = NULL;
                TEEC_SharedMemory *out_parent = NULL;

                for (unsigned i = 0;
                     i < AES_PG_CACHE_N;
                     i++) {

                    if (aes_in_pg[i].valid &&
                        aes_in_pg[i].base ==
                            (void *)in_base) {

                        in_parent =
                            &aes_in_pg[i].shm;
                    }

                    if (aes_out_pg[i].valid &&
                        aes_out_pg[i].base ==
                            (void *)out_base) {

                        out_parent =
                            &aes_out_pg[i].shm;
                    }
                }

                if (!in_parent ||
                    !out_parent) {

                    if (returnOrigin)
                        *returnOrigin =
                            TEEC_ORIGIN_API;

                    return TEEC_ERROR_BAD_STATE;
                }

                memset(&op2, 0, sizeof(op2));

                op2.paramTypes =
                    TEEC_PARAM_TYPES(
                        TEEC_MEMREF_PARTIAL_INPUT,
                        TEEC_MEMREF_PARTIAL_OUTPUT,
                        TEEC_NONE,
                        TEEC_NONE);

                op2.params[0].memref.parent =
                    in_parent;

                op2.params[0].memref.offset =
                    in_off;

                op2.params[0].memref.size =
                    in_len;

                op2.params[1].memref.parent =
                    out_parent;

                op2.params[1].memref.offset =
                    out_off;

                op2.params[1].memref.size =
                    in_len;

                r = TEEC_InvokeCommand(
                        target,
                        commandID,
                        &op2,
                        &origin);

                DBG_PRINT(
                    "AES ZC CACHE INVOKE: "
                    "in=%p off=%zu "
                    "out=%p off=%zu "
                    "len=%zu -> 0x%x "
                    "(origin=%u)",
                    in_buf,
                    in_off,
                    out_buf,
                    out_off,
                    in_len,
                    r,
                    origin);

                aes_zc_calls_in++;
                aes_zc_calls_out++;

                if (r == TEEC_SUCCESS)
                    p->output_size =
                        (unsigned long)in_len;

                if (returnOrigin)
                    *returnOrigin = origin;

                return r;
            }

            /*
             * ----------------------------------------------------
             * LARGE or IN-PLACE ZC
             * ----------------------------------------------------
             *
             * Large buffers cannot be registered as one giant SHM
             * object, so use bounded windows.
             *
             * In-place OpenSSL speed also uses this path because a
             * single INPUT|OUTPUT registration is safest there.
             */
            size_t offset = 0;
            size_t ps = titan_pagesz();

            while (offset < in_len) {

                size_t chunk =
                    in_len - offset;

                if (chunk > max_chunk)
                    chunk = max_chunk;

                uint8_t *in_ptr =
                    in_buf + offset;

                uint8_t *out_ptr =
                    out_buf + offset;

                bool inplace =
                    (in_ptr == out_ptr);

                memset(&op2, 0, sizeof(op2));

                if (inplace) {

                    uintptr_t p_u =
                        (uintptr_t)in_ptr;

                    uintptr_t base_u =
                        align_down_u(p_u, ps);

                    size_t shm_off =
                        (size_t)(p_u - base_u);

                    size_t shm_len =
                        shm_off + chunk;

                    TEEC_SharedMemory shm;
                    memset(&shm, 0, sizeof(shm));

                    shm.buffer =
                        (void *)base_u;

                    shm.size =
                        shm_len;

                    shm.flags =
                        TEEC_MEM_INPUT |
                        TEEC_MEM_OUTPUT;

                    r = TEEC_RegisterSharedMemory(
                            &real_ctx,
                            &shm);

                    aes_reg_calls++;

                    DBG_PRINT(
                        "AES ZC INPLACE REG: "
                        "off=%zu data=%zu "
                        "shm_off=%zu "
                        "shm_len=%zu -> 0x%x",
                        offset,
                        chunk,
                        shm_off,
                        shm_len,
                        r);

                    if (r != TEEC_SUCCESS) {
                        if (returnOrigin)
                            *returnOrigin =
                                TEEC_ORIGIN_API;

                        return r;
                    }

                    op2.paramTypes =
                        TEEC_PARAM_TYPES(
                            TEEC_MEMREF_PARTIAL_INPUT,
                            TEEC_MEMREF_PARTIAL_OUTPUT,
                            TEEC_NONE,
                            TEEC_NONE);

                    op2.params[0].memref.parent =
                        &shm;

                    op2.params[0].memref.offset =
                        shm_off;

                    op2.params[0].memref.size =
                        chunk;

                    op2.params[1].memref.parent =
                        &shm;

                    op2.params[1].memref.offset =
                        shm_off;

                    op2.params[1].memref.size =
                        chunk;

                    r = TEEC_InvokeCommand(
                            target,
                            commandID,
                            &op2,
                            &origin);

                    DBG_PRINT(
                        "AES ZC INPLACE INVOKE: "
                        "off=%zu len=%zu/%zu "
                        "-> 0x%x (origin=%u)",
                        offset,
                        chunk,
                        in_len,
                        r,
                        origin);

                    aes_zc_calls_in++;
                    aes_zc_calls_out++;

                    TEEC_ReleaseSharedMemory(&shm);
                    aes_rel_calls++;

                } else {

                    uintptr_t in_u =
                        (uintptr_t)in_ptr;

                    uintptr_t out_u =
                        (uintptr_t)out_ptr;

                    uintptr_t in_base_u =
                        align_down_u(in_u, ps);

                    uintptr_t out_base_u =
                        align_down_u(out_u, ps);

                    size_t in_off =
                        (size_t)(in_u -
                                 in_base_u);

                    size_t out_off =
                        (size_t)(out_u -
                                 out_base_u);

                    TEEC_SharedMemory in_shm;
                    TEEC_SharedMemory out_shm;

                    memset(&in_shm, 0,
                           sizeof(in_shm));

                    memset(&out_shm, 0,
                           sizeof(out_shm));

                    in_shm.buffer =
                        (void *)in_base_u;

                    in_shm.size =
                        in_off + chunk;

                    in_shm.flags =
                        TEEC_MEM_INPUT;

                    out_shm.buffer =
                        (void *)out_base_u;

                    out_shm.size =
                        out_off + chunk;

                    out_shm.flags =
                        TEEC_MEM_OUTPUT;

                    r = TEEC_RegisterSharedMemory(
                            &real_ctx,
                            &in_shm);

                    aes_reg_calls++;

                    if (r != TEEC_SUCCESS) {
                        if (returnOrigin)
                            *returnOrigin =
                                TEEC_ORIGIN_API;

                        return r;
                    }

                    TEEC_Result rr =
                        TEEC_RegisterSharedMemory(
                            &real_ctx,
                            &out_shm);

                    aes_reg_calls++;

                    if (rr != TEEC_SUCCESS) {

                        TEEC_ReleaseSharedMemory(
                            &in_shm);

                        aes_rel_calls++;

                        if (returnOrigin)
                            *returnOrigin =
                                TEEC_ORIGIN_API;

                        return rr;
                    }

                    op2.paramTypes =
                        TEEC_PARAM_TYPES(
                            TEEC_MEMREF_PARTIAL_INPUT,
                            TEEC_MEMREF_PARTIAL_OUTPUT,
                            TEEC_NONE,
                            TEEC_NONE);

                    op2.params[0].memref.parent =
                        &in_shm;

                    op2.params[0].memref.offset =
                        in_off;

                    op2.params[0].memref.size =
                        chunk;

                    op2.params[1].memref.parent =
                        &out_shm;

                    op2.params[1].memref.offset =
                        out_off;

                    op2.params[1].memref.size =
                        chunk;

                    r = TEEC_InvokeCommand(
                            target,
                            commandID,
                            &op2,
                            &origin);

                    DBG_PRINT(
                        "AES ZC WINDOW INVOKE: "
                        "off=%zu len=%zu/%zu "
                        "-> 0x%x (origin=%u)",
                        offset,
                        chunk,
                        in_len,
                        r,
                        origin);

                    aes_zc_calls_in++;
                    aes_zc_calls_out++;

                    TEEC_ReleaseSharedMemory(
                            &out_shm);

                    aes_rel_calls++;

                    TEEC_ReleaseSharedMemory(
                            &in_shm);

                    aes_rel_calls++;
                }

                if (r != TEEC_SUCCESS) {
                    if (returnOrigin)
                        *returnOrigin = origin;

                    return r;
                }

                offset += chunk;
            }

            p->output_size =
                (unsigned long)in_len;

            if (returnOrigin)
                *returnOrigin = origin;

            return TEEC_SUCCESS;
        }

        /*
         * ========================================================
         * TEMP / ZX
         * ========================================================
         */
        size_t offset = 0;

        while (offset < in_len) {

            size_t chunk =
                in_len - offset;

            if (chunk > max_chunk)
                chunk = max_chunk;

            memset(&op2, 0, sizeof(op2));

            op2.paramTypes =
                TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_MEMREF_TEMP_OUTPUT,
                    TEEC_NONE,
                    TEEC_NONE);

            op2.params[0].tmpref.buffer =
                in_buf + offset;

            op2.params[0].tmpref.size =
                chunk;

            op2.params[1].tmpref.buffer =
                out_buf + offset;

            op2.params[1].tmpref.size =
                chunk;

            r = TEEC_InvokeCommand(
                    target,
                    commandID,
                    &op2,
                    &origin);

            DBG_PRINT(
                "AES TMP CHUNK: "
                "off=%zu len=%zu/%zu "
                "-> 0x%x (origin=%u)",
                offset,
                chunk,
                in_len,
                r,
                origin);

            aes_tmp_calls_in++;
            aes_tmp_calls_out++;

            if (r != TEEC_SUCCESS) {
                if (returnOrigin)
                    *returnOrigin = origin;

                return r;
            }

            offset += chunk;
        }

        p->output_size =
            (unsigned long)in_len;

        if (returnOrigin)
            *returnOrigin = origin;

        return TEEC_SUCCESS;
    }


   if (commandID == TITANSSL_CMD_AES_CLEANUP) {
    TEEC_Operation op2c; memset(&op2c, 0, sizeof(op2c));
    op2c.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    uint32_t origin2 = 0;
    TEEC_Result rc = TEEC_InvokeCommand(target, commandID, &op2c, &origin2);

    for (unsigned i = 0; i < AES_PG_CACHE_N; i++) {
    if (aes_in_pg[i].valid) {
        TEEC_ReleaseSharedMemory(&aes_in_pg[i].shm);
        aes_rel_calls++;
        aes_in_pg[i].valid = false;
        aes_in_pg[i].base = NULL;
        aes_in_pg[i].cap = 0;
    }
    if (aes_out_pg[i].valid) {
        TEEC_ReleaseSharedMemory(&aes_out_pg[i].shm);
        aes_rel_calls++;
        aes_out_pg[i].valid = false;
        aes_out_pg[i].base = NULL;
        aes_out_pg[i].cap = 0;
    }
}


    /* Also release old pointer-caches if you kept them (optional safety) */
    if (aes_in_zc.valid)  { TEEC_ReleaseSharedMemory(&aes_in_zc.shm);  aes_rel_calls++; aes_in_zc.valid  = false; aes_in_zc.ptr  = NULL; aes_in_zc.size  = 0; }
    if (aes_out_zc.valid) { TEEC_ReleaseSharedMemory(&aes_out_zc.shm); aes_rel_calls++; aes_out_zc.valid = false; aes_out_zc.ptr = NULL; aes_out_zc.size = 0; }

    if (returnOrigin) *returnOrigin = origin2;
    DBG_PRINT("AES CLEANUP: result=0x%x (origin=%u)", rc, origin2);
    return rc;
}


   
    if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
    return TEEC_ERROR_NOT_SUPPORTED;
}
