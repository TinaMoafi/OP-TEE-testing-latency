#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TITANSSL_WRAPPER_INTERNAL 1
#include "tee_client_api_wrapper.h"
#include "titanssl_common.h"
#include "uuid_ta.h"
#include <tee_client_api.h>

#define DBG_PRINT(...) do { \
    fprintf(stderr, "[DEBUG] %s:%d: ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); \
} while (0)

struct tiny_sess { uint32_t token, reserved; };
#define TINY_TOKEN 0x54534553u
#define TINY(p) ((struct tiny_sess*)(void*)(p))

struct legacy_operation {
    uint32_t started;
    uint32_t paramTypes;
    void    *data_in_addr;
    void    *data_out_addr;
    size_t   data_size;
    TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
};

static TEEC_Context  real_ctx;
static TEEC_Session  real_sess_rsa;
static int           initialized = 0;
static int           rsa_opened  = 0;

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
            if (L >= 64 && L <= 2048) {
                *nbytes_out = L;
                return 0;
            }
        }
    }
    return -1;
}

static TEEC_Result ensure_rsa_session_open(uint32_t *origin)
{
    if (!initialized) return TEEC_ERROR_BAD_STATE;
    if (rsa_opened)   return TEEC_SUCCESS;
    TEEC_Result r = TEEC_OpenSession(&real_ctx, &real_sess_rsa, &RSA_TA_UUID,
                                     TEEC_LOGIN_PUBLIC, NULL, NULL, origin);
    if (r == TEEC_SUCCESS) rsa_opened = 1;
    return r;
}

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

    if (context) context->fd = 1;
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

    if (commandID == TITANSSL_CMD_RSA_DOCIPHER) {
        const uint32_t expect =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                             TEEC_MEMREF_TEMP_INPUT,
                             TEEC_MEMREF_TEMP_OUTPUT,
                             TEEC_MEMREF_TEMP_INPUT);
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

        titanssl_meta_rsa_t meta;
        memcpy(&meta, p3->buffer, sizeof(meta));

        if (in_len != meta.ksize) {
            if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
            DBG_PRINT("Input %lu != ksize %u", (unsigned long)in_len, meta.ksize);
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        meta.input_len = (uint32_t)in_len;

        titanssl_parameters_t phdr;
        memset(&phdr, 0, sizeof(phdr));
        phdr.cmd         = TITANSSL_CMD_RSA_DOCIPHER;
        phdr.input_size  = (unsigned long)meta.input_len;
        phdr.output_size = (unsigned long)out_len;
        phdr.meta_size   = (unsigned long)sizeof(titanssl_meta_rsa_t);

        TEEC_Operation op2;
        memset(&op2, 0, sizeof(op2));
        op2.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                          TEEC_MEMREF_TEMP_INPUT,
                                          TEEC_MEMREF_TEMP_OUTPUT,
                                          TEEC_MEMREF_TEMP_INPUT);
        op2.params[0].tmpref.buffer = &phdr;
        op2.params[0].tmpref.size   = sizeof(phdr);
        op2.params[1].tmpref.buffer = in_buf;
        op2.params[1].tmpref.size   = in_len;
        op2.params[2].tmpref.buffer = out_buf;
        op2.params[2].tmpref.size   = out_len;
        op2.params[3].tmpref.buffer = &meta;
        op2.params[3].tmpref.size   = sizeof(meta);

        r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DOCIPHER, &op2, &origin);
        DBG_PRINT("DOCIPHER -> 0x%x (origin=%u), out.size=%lu",
                  r, origin, (unsigned long)op2.params[2].tmpref.size);

        if (r != TEEC_SUCCESS && meta.kid > 0) {
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
                            DBG_PRINT("AUTO-IMPORT succeeded, retrying DOCIPHER...");
                            op2.params[2].tmpref.size = out_len;
                            r = TEEC_InvokeCommand(&real_sess_rsa, TITANSSL_CMD_RSA_DOCIPHER, &op2, &origin);
                            DBG_PRINT("DOCIPHER(retry) -> 0x%x (origin=%u), out.size=%lu",
                                      r, origin, (unsigned long)op2.params[2].tmpref.size);
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

        if (r == TEEC_SUCCESS) {
            ((titanssl_parameters_t*)p0->buffer)->output_size =
                (unsigned long)op2.params[2].tmpref.size;
        }
        if (returnOrigin) *returnOrigin = origin;
        return r;
    }

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

    DBG_PRINT("Pass-through CMD=%u", commandID);
    r = TEEC_InvokeCommand(&real_sess_rsa, commandID, (TEEC_Operation*)operation, &origin);
    if (returnOrigin) *returnOrigin = origin;
    return r;
}
