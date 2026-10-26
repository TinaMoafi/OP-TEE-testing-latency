#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>           

#define TITANSSL_WRAPPER_INTERNAL 1
#include "tee_client_api_wrapper.h"
#include "titanssl_common.h"
#include "uuid_ta.h"
#include <tee_client_api.h>

/* --------------------------- Debug macro --------------------------- */
#define DBG_PRINT(...) do { \
    fprintf(stderr, "[DEBUG] %s:%d: ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); \
} while (0)

/* ============================ Tiny session tag ============================ */
struct tiny_sess { uint32_t token, reserved; };
#define TINY_TOKEN 0x54534553u
#define TINY(p) ((struct tiny_sess*)(void*)(p))

/* ========================= Legacy op view from engine ===================== */
struct legacy_operation {
    uint32_t started;
    uint32_t paramTypes;
    void    *data_in_addr;
    void    *data_out_addr;
    size_t   data_size;
    TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

/* ============================ Real OP-TEE state =========================== */
static TEEC_Context  real_ctx;
static TEEC_Session  real_sess_rsa;
static int           initialized = 0;
static int           rsa_opened  = 0;

/* =============================== Keyring hook ============================= */
typedef struct {
    unsigned int kid;
    unsigned int ktype;
    const unsigned char *blob;
    unsigned int blob_len;
} titanssl_key_entry_t;

__attribute__((weak))
const titanssl_key_entry_t*
titanssl_keyring_lookup(unsigned int kid, unsigned int ktype) {
    (void)kid; (void)ktype;
    return NULL;
}

/* =============================== ZC helpers =============================== */
#ifndef TITANSSL_ZC_THRESHOLD
#define TITANSSL_ZC_THRESHOLD 8192   /* bytes; tune per platform */
#endif

static inline int use_zerocopy(size_t n) { return (int)(n >= TITANSSL_ZC_THRESHOLD); }

/* Runtime override via env (read each time for simplicity) */
static inline int zc_forced_on(void)  { const char *s=getenv("TITANSSL_ZC_FORCE"); return s && strcmp(s,"1")==0; }
static inline int zc_forced_off(void) { const char *s=getenv("TITANSSL_ZC_FORCE"); return s && strcmp(s,"0")==0; }

/* Timing helper (ns) */
static inline uint64_t nsec_now(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Diagnostics counters */
static size_t rsa_zc_calls_in  = 0, rsa_tmp_calls_in  = 0;
static size_t rsa_zc_calls_out = 0, rsa_tmp_calls_out = 0;
static size_t rsa_reg_calls    = 0, rsa_rel_calls     = 0;

/* Optional aggregate timings (TA hop only) */
static uint64_t rsa_calls = 0, rsa_ns_sum = 0, rsa_ns_min = ~0ULL, rsa_ns_max = 0;

/* ============== Utility: guess modulus length from DER blob (optional) ============== */
static int key_blob_guess_modulus_bytes(const uint8_t *der, size_t der_len, size_t *nbytes_out)
{
    if (!der || der_len < 8) return -1;
    for (size_t i = 0; i + 3 < der_len; ++i) {
        if (der[i] == 0x02) {
            size_t len = 0, lc = 0;
            uint8_t b = der[i+1];
            if ((b & 0x80) == 0) { len = b; lc = 1; }
            else {
                size_t n = b & 0x7F;
                if (n == 0 || n > 4 || i + 2 + n >= der_len) continue;
                size_t v = 0;
                for (size_t j=0; j<n; ++j) v = (v<<8) | der[i+2+j];
                len = v; lc = 1 + n;
            }
            if (i + 1 + lc + len > der_len) continue;
            const uint8_t *p = der + i + 1 + lc;
            size_t L = len;
            while (L > 0 && *p == 0x00) { ++p; --L; }
            if (L >= 64 && L <= 2048) { *nbytes_out = L; return 0; }
        }
    }
    return -1;
}

/* ============================= Session helpers =========================== */
static TEEC_Result ensure_rsa_session_open(uint32_t *origin)
{
    if (!initialized) return TEEC_ERROR_BAD_STATE;
    if (rsa_opened)   return TEEC_SUCCESS;
    TEEC_Result r = TEEC_OpenSession(&real_ctx, &real_sess_rsa, &RSA_TA_UUID,
                                     TEEC_LOGIN_PUBLIC, NULL, NULL, origin);
    if (r == TEEC_SUCCESS) rsa_opened = 1;
    return r;
}

/* ============================ Wrapper utilities =========================== */
static TEEC_Result wrapper_import_kid(const titanssl_meta_rsa_t *meta_in, uint32_t *origin_out)
{
    titanssl_parameters_t phdr;
    TEEC_Operation op2;
    uint32_t origin = 0;

    if (!meta_in || meta_in->kid == 0 || meta_in->blob_len == 0)
        return TEEC_ERROR_BAD_PARAMETERS;

    memset(&phdr, 0, sizeof(phdr));
    phdr.cmd       = TITANSSL_CMD_RSA_IMPORT;
    phdr.meta_size = (unsigned long)sizeof(titanssl_meta_rsa_t);

    memset(&op2, 0, sizeof(op2));
    op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_NONE,
                                      TEEC_NONE,
                                      TEEC_MEMREF_TEMP_INPUT);
    op2.params[0].tmpref.buffer = &phdr;
    op2.params[0].tmpref.size   = sizeof(phdr);
    op2.params[3].tmpref.buffer = (void*)meta_in;
    op2.params[3].tmpref.size   = sizeof(*meta_in);

    TEEC_Result r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_IMPORT, &op2, &origin);
    if (origin_out) *origin_out = origin;
    return r;
}

/* ============================== Public API =============================== */
TEEC_Result TitanSSL_TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    (void)name;
    DBG_PRINT("Enter");
    if (!initialized) {
        uint32_t origin = 0;
        TEEC_Result r;

        DBG_PRINT("Calling real TEEC_InitializeContext");
        r = TEEC_InitializeContext(NULL, &real_ctx);
        DBG_PRINT("TEEC_InitializeContext -> 0x%x", r);
        if (r != TEEC_SUCCESS) return r;

        DBG_PRINT("Opening real TEEC session to RSA TA");
        r = TEEC_OpenSession(&real_ctx, &real_sess_rsa, &RSA_TA_UUID,
                             TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
        DBG_PRINT("TEEC_OpenSession(RSA) -> 0x%x (origin=%u)", r, origin);
        if (r == TEEC_SUCCESS) rsa_opened = 1;

        initialized = 1;
    }

    if (context) context->imp.fd  = 1; /* engine expects a non-zero marker */
    DBG_PRINT("Exit");
    return TEEC_SUCCESS;
}

void TitanSSL_TEEC_FinalizeContext(TEEC_Context *context)
{
    (void)context;
    DBG_PRINT("Enter");
    if (initialized) {
        if (rsa_opened) {
            TEEC_CloseSession(&real_sess_rsa);
            rsa_opened = 0;
        }
        TEEC_FinalizeContext(&real_ctx);
        initialized = 0;

        if (rsa_calls) {
            double avg_us = (double)rsa_ns_sum / (double)rsa_calls / 1000.0;
            DBG_PRINT("RSA TA-hop timing: calls=%llu avg=%.2f us min=%.2f us max=%.2f us",
                      (unsigned long long)rsa_calls,
                      avg_us, rsa_ns_min/1000.0, rsa_ns_max/1000.0);
        }
        DBG_PRINT("RSA ZC stats: in_zc=%zu in_tmp=%zu out_zc=%zu out_tmp=%zu reg=%zu rel=%zu",
                  rsa_zc_calls_in, rsa_tmp_calls_in, rsa_zc_calls_out, rsa_tmp_calls_out,
                  rsa_reg_calls, rsa_rel_calls);
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
    (void)context; (void)destination; (void)connectionMethod; (void)connectionData; (void)operation;
    DBG_PRINT("Enter");
    if (!session) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        DBG_PRINT("Bad parameters");
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    TINY(session)->token = TINY_TOKEN;
    if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
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
    if (!operation) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        DBG_PRINT("No TEEC_Operation provided");
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    struct legacy_operation *lop = (struct legacy_operation *)(void *)operation;

    TEEC_TempMemoryReference *p0 = &lop->params[0].tmpref;
    TEEC_TempMemoryReference *p1 = &lop->params[1].tmpref;
    TEEC_TempMemoryReference *p2 = &lop->params[2].tmpref;
    TEEC_TempMemoryReference *p3 = &lop->params[3].tmpref;

    uint32_t origin = 0;
    TEEC_Result r = ensure_rsa_session_open(&origin);
    DBG_PRINT("ensure_rsa_session_open -> 0x%x (origin=%u)", r, origin);
    if (r != TEEC_SUCCESS) { if (returnOrigin) *returnOrigin = origin; return r; }

    /* ============================== RSA DOCIPHER ============================== */
    if (commandID == TITANSSL_CMD_RSA_DOCIPHER) {
        DBG_PRINT("RSA DOCIPHER: reached (build ZC threshold=%d)", (int)TITANSSL_ZC_THRESHOLD);

        const uint32_t expect =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,   /* header/control block (tiny) */
                             TEEC_MEMREF_TEMP_INPUT,   /* input payload */
                             TEEC_MEMREF_TEMP_OUTPUT,  /* output payload */
                             TEEC_MEMREF_TEMP_INPUT);  /* meta (tiny) */

        DBG_PRINT("DOCIPHER: operation->paramTypes=0x%08x expect=0x%08x",
                  lop->paramTypes, expect);
        if (lop->paramTypes != expect) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Bad paramTypes");
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        if (!p0->buffer || p0->size < sizeof(titanssl_parameters_t) ||
            !p1->buffer || !p2->buffer || !p3->buffer ||
            p3->size < sizeof(titanssl_meta_rsa_t)) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Null/size check failed");
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        void  *in_buf   = p1->buffer;
        size_t in_len   = p1->size;
        void  *out_buf  = p2->buffer;
        size_t out_len  = p2->size;

        DBG_PRINT("RSA DOCIPHER: sizes in_len=%zu out_len=%zu", in_len, out_len);

        /* Copy meta locally so we can tweak input_len safely */
        titanssl_meta_rsa_t meta;
        memcpy(&meta, p3->buffer, sizeof(meta));

        if (in_len != meta.ksize) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Input %lu != ksize %u", (unsigned long)in_len, meta.ksize);
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        meta.input_len = (uint32_t)in_len;

        /* Prepare tiny header (temp is fine) */
        titanssl_parameters_t phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.cmd         = TITANSSL_CMD_RSA_DOCIPHER;
        phdr.input_size  = (unsigned long)meta.input_len;
        phdr.output_size = (unsigned long)out_len;
        phdr.meta_size   = (unsigned long)sizeof(titanssl_meta_rsa_t);

        /* Build a fresh op for the TA */
        TEEC_Operation op2;
        memset(&op2, 0, sizeof(op2));

        /* Decide ZC vs TEMP (with env override) */
        int want_zc = (use_zerocopy(in_len) || use_zerocopy(out_len));
        const char *why = want_zc ? ">= threshold" : "< threshold";
        if (zc_forced_on())  { want_zc = 1; why = "forced ON by env"; }
        if (zc_forced_off()) { want_zc = 0; why = "forced OFF by env"; }
        DBG_PRINT("RSA DOCIPHER: want_zc=%d (%s)", want_zc, why);

        if (want_zc) {
            TEEC_SharedMemory shm_in  = (TEEC_SharedMemory){0};
            TEEC_SharedMemory shm_out = (TEEC_SharedMemory){0};

            /* Register existing engine buffers (zero-copy) */
            shm_in.buffer = in_buf;
            shm_in.size   = in_len;
            shm_in.flags  = TEEC_MEM_INPUT;

            shm_out.buffer = out_buf;
            shm_out.size   = out_len;
            shm_out.flags  = TEEC_MEM_OUTPUT;

            DBG_PRINT("RSA DOCIPHER ZC: attempting RegisterSharedMemory IN=%p len=%zu OUT=%p len=%zu",
                      in_buf, in_len, out_buf, out_len);

            r = TEEC_RegisterSharedMemory(&real_ctx, &shm_in);
            if (r != TEEC_SUCCESS) {
                DBG_PRINT("RSA DOCIPHER ZC: Reg IN failed 0x%x -> TEMP fallback", r);
                goto docipher_temp_path;
            }
            rsa_reg_calls++;

            r = TEEC_RegisterSharedMemory(&real_ctx, &shm_out);
            if (r != TEEC_SUCCESS) {
                DBG_PRINT("RSA DOCIPHER ZC: Reg OUT failed 0x%x -> TEMP fallback", r);
                TEEC_ReleaseSharedMemory(&shm_in); rsa_rel_calls++;
                goto docipher_temp_path;
            }
            rsa_reg_calls++;

            op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,      /* header */
                                              TEEC_MEMREF_PARTIAL_INPUT,   /* in  (ZC) */
                                              TEEC_MEMREF_PARTIAL_OUTPUT,  /* out (ZC) */
                                              TEEC_MEMREF_TEMP_INPUT);     /* meta */

            /* header/meta */
            op2.params[0].tmpref.buffer = &phdr;
            op2.params[0].tmpref.size   = sizeof(phdr);
            op2.params[3].tmpref.buffer = &meta;
            op2.params[3].tmpref.size   = sizeof(meta);

            /* payloads as PARTIAL on registered parents */
            op2.params[1].memref.parent = &shm_in;
            op2.params[1].memref.offset = 0;
            op2.params[1].memref.size   = in_len;

            op2.params[2].memref.parent = &shm_out;
            op2.params[2].memref.offset = 0;
            op2.params[2].memref.size   = out_len; /* TA will shrink to produced */

            DBG_PRINT("RSA DOCIPHER ZC: using PARTIAL memrefs, invoking TA...");
            uint64_t t0 = nsec_now();
            r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DOCIPHER, &op2, &origin);
            uint64_t dt = nsec_now() - t0;

            rsa_calls++; rsa_ns_sum += dt;
            if (dt < rsa_ns_min) rsa_ns_min = dt;
            if (dt > rsa_ns_max) rsa_ns_max = dt;

            DBG_PRINT("DOCIPHER (ZC) -> 0x%x (origin=%u), out.size=%lu, TA hop %.3f ms",
                      r, origin, (unsigned long)op2.params[2].memref.size, dt/1e6);

            /* Reflect produced size */
            if (r == TEEC_SUCCESS) {
                ((titanssl_parameters_t*)p0->buffer)->output_size =
                    (unsigned long)op2.params[2].memref.size;
                rsa_zc_calls_in++; rsa_zc_calls_out++;
            }

            TEEC_ReleaseSharedMemory(&shm_in);  rsa_rel_calls++;
            TEEC_ReleaseSharedMemory(&shm_out); rsa_rel_calls++;

            if (returnOrigin) *returnOrigin = origin;
            return r;
        }

docipher_temp_path:
        /* TEMP (copy) path */
        op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,   /* header */
                                          TEEC_MEMREF_TEMP_INPUT,   /* in  */
                                          TEEC_MEMREF_TEMP_OUTPUT,  /* out */
                                          TEEC_MEMREF_TEMP_INPUT);  /* meta */

        op2.params[0].tmpref.buffer = &phdr;
        op2.params[0].tmpref.size   = sizeof(phdr);

        op2.params[1].tmpref.buffer = in_buf;
        op2.params[1].tmpref.size   = in_len;

        op2.params[2].tmpref.buffer = out_buf;
        op2.params[2].tmpref.size   = out_len;

        op2.params[3].tmpref.buffer = &meta;
        op2.params[3].tmpref.size   = sizeof(meta);

        DBG_PRINT("RSA DOCIPHER (TEMP path taken), invoking TA...");
        uint64_t t0 = nsec_now();
        r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DOCIPHER, &op2, &origin);
        uint64_t dt = nsec_now() - t0;

        rsa_calls++; rsa_ns_sum += dt;
        if (dt < rsa_ns_min) rsa_ns_min = dt;
        if (dt > rsa_ns_max) rsa_ns_max = dt;

        DBG_PRINT("DOCIPHER (TEMP) -> 0x%x (origin=%u), out.size=%lu, TA hop %.3f ms",
                  r, origin, (unsigned long)op2.params[2].tmpref.size, dt/1e6);

        if (r == TEEC_SUCCESS) {
            ((titanssl_parameters_t*)p0->buffer)->output_size =
                (unsigned long)op2.params[2].tmpref.size;
            rsa_tmp_calls_in++; rsa_tmp_calls_out++;
        }

        if (r != TEEC_SUCCESS && meta.kid > 0) {
            /* Optional: auto-import & retry for secure-mode keys */
            const titanssl_key_entry_t *ent = titanssl_keyring_lookup(meta.kid, meta.ktype);
            if (ent && ent->blob && ent->blob_len > 0) {
                size_t nbytes = 0;
                if (key_blob_guess_modulus_bytes(ent->blob, ent->blob_len, &nbytes) == 0 &&
                    nbytes > 0 && nbytes <= TITANSSL_RSA_KEY_BLOB_MAX) {

                    titanssl_meta_rsa_t im;
                    memset(&im, 0, sizeof(im));
                    im.kid      = meta.kid;
                    im.ktype    = meta.ktype;
                    im.ksize    = (uint32_t)nbytes;
                    im.blob_len = ent->blob_len;

                    if (im.blob_len <= TITANSSL_RSA_KEY_BLOB_MAX) {
                        memcpy(im.key_blob, ent->blob, ent->blob_len);

                        uint32_t o2 = 0;
                        TEEC_Result ir = wrapper_import_kid(&im, &o2);
                        if (ir == TEEC_SUCCESS) {
                            DBG_PRINT("AUTO-IMPORT succeeded, retrying DOCIPHER (TEMP)...");
                            /* reset out size and retry TEMP path quickly */
                            op2.params[2].tmpref.size = out_len;
                            t0 = nsec_now();
                            r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DOCIPHER, &op2, &origin);
                            dt = nsec_now() - t0;

                            rsa_calls++; rsa_ns_sum += dt;
                            if (dt < rsa_ns_min) rsa_ns_min = dt;
                            if (dt > rsa_ns_max) rsa_ns_max = dt;

                            DBG_PRINT("DOCIPHER(retry TEMP) -> 0x%x (origin=%u), out.size=%lu, TA hop %.3f ms",
                                      r, origin, (unsigned long)op2.params[2].tmpref.size, dt/1e6);
                            if (r == TEEC_SUCCESS) {
                                ((titanssl_parameters_t*)p0->buffer)->output_size =
                                    (unsigned long)op2.params[2].tmpref.size;
                            }
                        } else {
                            DBG_PRINT("AUTO-IMPORT failed 0x%x (origin=%u)", ir, o2);
                        }
                    } else {
                        DBG_PRINT("AUTO-IMPORT: blob too large (%u > %u)",
                                  im.blob_len, (unsigned)TITANSSL_RSA_KEY_BLOB_MAX);
                    }
                } else {
                    DBG_PRINT("AUTO-IMPORT: cannot determine modulus size from DER (kid=%u).", meta.kid);
                }
            } else {
                DBG_PRINT("No compat keyring entry for kid=%u ktype=%u; skip auto-import.", meta.kid, meta.ktype);
            }
        }

        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

    /* ============================== RSA IMPORT =============================== */
    if (commandID == TITANSSL_CMD_RSA_IMPORT) {
        const uint32_t expect =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                             TEEC_NONE,
                             TEEC_NONE,
                             TEEC_MEMREF_TEMP_INPUT);
        DBG_PRINT("IMPORT: operation->paramTypes=0x%08x expect=0x%08x",
                  lop->paramTypes, expect);
        if (lop->paramTypes != expect ||
            !p0->buffer || p0->size < sizeof(titanssl_parameters_t) ||
            !p3->buffer || p3->size < sizeof(titanssl_meta_rsa_t)) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Bad params");
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        titanssl_parameters_t phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.cmd       = TITANSSL_CMD_RSA_IMPORT;
        phdr.meta_size = (unsigned long)sizeof(titanssl_meta_rsa_t);

        titanssl_meta_rsa_t meta;
        memcpy(&meta, p3->buffer, sizeof(meta));

        if (meta.kid == 0 || meta.blob_len == 0) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("IMPORT: invalid kid or empty blob");
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        TEEC_Operation op2;
        memset(&op2, 0, sizeof(op2));
        op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                          TEEC_NONE,
                                          TEEC_NONE,
                                          TEEC_MEMREF_TEMP_INPUT);
        op2.params[0].tmpref.buffer = &phdr;
        op2.params[0].tmpref.size   = sizeof(phdr);
        op2.params[3].tmpref.buffer = &meta;
        op2.params[3].tmpref.size   = sizeof(meta);

        r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_IMPORT, &op2, &origin);
        DBG_PRINT("IMPORT -> 0x%x (origin=%u)", r, origin);
        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

    /* ============================== RSA DELETE =============================== */
    if (commandID == TITANSSL_CMD_RSA_DELETE) {
        const uint32_t expect =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                             TEEC_NONE,
                             TEEC_NONE,
                             TEEC_MEMREF_TEMP_INPUT);
        DBG_PRINT("DELETE: operation->paramTypes=0x%08x expect=0x%08x",
                  lop->paramTypes, expect);
        if (lop->paramTypes != expect ||
            !p0->buffer || p0->size < sizeof(titanssl_parameters_t) ||
            !p3->buffer || p3->size < sizeof(titanssl_meta_rsa_t)) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Bad params");
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        titanssl_parameters_t phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.cmd       = TITANSSL_CMD_RSA_DELETE;
        phdr.meta_size = (unsigned long)sizeof(titanssl_meta_rsa_t);

        titanssl_meta_rsa_t meta;
        memcpy(&meta, p3->buffer, sizeof(meta));

        if (meta.kid == 0) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("DELETE: invalid kid");
            return TEEC_ERROR_BAD_PARAMETERS;
        }

        TEEC_Operation op2;
        memset(&op2, 0, sizeof(op2));
        op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                          TEEC_NONE,
                                          TEEC_NONE,
                                          TEEC_MEMREF_TEMP_INPUT);
        op2.params[0].tmpref.buffer = &phdr;
        op2.params[0].tmpref.size   = sizeof(phdr);
        op2.params[3].tmpref.buffer = &meta;
        op2.params[3].tmpref.size   = sizeof(meta);

        r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DELETE, &op2, &origin);
        DBG_PRINT("DELETE -> 0x%x (origin=%u)", r, origin);
        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

    /* ============================== Pass-through ============================= */
    DBG_PRINT("Pass-through CMD=%u", commandID);
    r = TEEC_InvokeCommand(&real_sess_rsa, commandID, (TEEC_Operation*)operation, &origin);
    if (returnOrigin) *returnOrigin = origin;
    return r;
}
