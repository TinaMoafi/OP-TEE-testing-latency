// C stdlib
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// OpenSSL
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>

// OpenSSL headers for RSA, X509, ASN.1, etc.
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>



// TitanSSL
#include "tee_client_api.h"
#include "tee_client_api_wrapper.h"

#include "titanssl_common.h"

#define TITANSSL_RSA_OP_PUB_ENC   0  // Privacy
#define TITANSSL_RSA_OP_PRIV_DEC  1
#define TITANSSL_RSA_OP_PUB_DEC   2  // Authentication
#define TITANSSL_RSA_OP_PRIV_ENC  3



/******************************************************************************/
// Debugging Macros
#define TITANSSL_VERBOSE

#ifdef TITANSSL_VERBOSE
  #define titanssl_info(...)         fprintf(stdout, __VA_ARGS__)
  #define titanssl_debug(...)        fprintf(stderr, __VA_ARGS__)
  #define print_bignum(...)          _print_bignum(__VA_ARGS__)
  #define print_bytestream(...)      _print_bytestream(__VA_ARGS__)
#else
  #define titanssl_info(...)
  #define titanssl_debug(...)
  #define print_bignum(...)
  #define print_bytestream(...)
#endif

#define titanssl_error(...) fprintf(stderr, __VA_ARGS__)

// Byte stream printer (hex viewer for debugging)
static void _print_bytestream(const unsigned char *s, int n) {
    if (!s || n <= 0) {
        fprintf(stderr, "[DEBUG][bytestream] Invalid input\n");
        return;
    }

    fprintf(stderr, "[DEBUG][bytestream] Dump (%d bytes):\n", n);
    for (int i = 0; i < n; ++i) {
        fprintf(stderr, "%02X", s[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
        else fprintf(stderr, " ");
    }
    if (n % 16 != 0) fprintf(stderr, "\n");
}



/******************************************************************************/
// ENGINE metadata
static const char *engine_id = "titanssl_agnostic";
static const char *engine_name = "TitanSSL engine by UNIBO";

// ENGINE lifecycle
int engine_init(ENGINE *e);
int engine_finish(ENGINE *e);
int engine_destroy(ENGINE *e);

// ENGINE registration
int bind_helper(ENGINE *e, const char *id);
int bind_helper_rsa(ENGINE *e, const char *id);
int engine_set_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
int engine_set_cipher(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);

// --- DIGEST: SHA-256 ---
int sha256_init(EVP_MD_CTX *ctx);
int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sha256_final(EVP_MD_CTX *ctx, unsigned char *md);
int sha256_cleanup(EVP_MD_CTX *ctx);

// --- CIPHER: AES-256-CBC ---
int aes_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int aes_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int aes_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int aes_cleanup(EVP_CIPHER_CTX *ctx);

// --- RSA core methods ---
int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding, bool pre_padded);
int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

// RSA OpenSSL adapter 
int rsa_priv_enc_adapter(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

// RSA EVP methods (for EVP_PKEY)
int titanssl_rsa_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
int titanssl_rsa_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

// RSA lifecycle
int rsa_init(RSA *rsa);
int rsa_finish(RSA *rsa);

// Key loading hooks
EVP_PKEY *titanssl_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *titanssl_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);

/******************************************************************************/
// Globals
static TEEC_Context *titanssl_teec_context = NULL;
static EVP_MD *titanssl_evp_md = NULL;
static EVP_CIPHER *titanssl_evp_cipher = NULL;
static RSA_METHOD *titanssl_rsa_method = NULL;

/******************************************************************************/
// ENGINE BINDING
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()


int bind_helper(ENGINE *e, const char *id) {
    titanssl_info("[ENGINE][bind_helper]\n");

    if (!id || strcmp(id, "titanssl_agnostic") != 0) {
        titanssl_error("[ENGINE][bind_helper] Error: Wrong engine ID '%s'\n", id);
        return 0;
    }

    if (!ENGINE_set_id(e, engine_id) ||
        !ENGINE_set_name(e, engine_name) ||
        !ENGINE_set_init_function(e, engine_init) ||
        !ENGINE_set_finish_function(e, engine_finish) ||
        !ENGINE_set_destroy_function(e, engine_destroy)) {
        titanssl_error("[ENGINE][bind_helper] Error in ENGINE basic setup\n");
        return 0;
    }

    if (!ENGINE_set_digests(e, engine_set_digests)) {
        titanssl_error("[ENGINE][bind_helper] Error in ENGINE_set_digests\n");
        return 0;
    }

    if (!ENGINE_set_ciphers(e, engine_set_cipher)) {
        titanssl_error("[ENGINE][bind_helper] Error in ENGINE_set_ciphers\n");
        return 0;
    }

  
	if(!bind_helper_rsa(e, id)){
    titanssl_error("[ENGINE][bind_helper] Error in bind_helper_rsa\n"); 
    return 0;
    }


    titanssl_info("[ENGINE][bind_helper] TitanSSL Engine successfully bound\n");
    return 1;
}

/******************************************************************************/
//engine lifecycle
int engine_init(ENGINE *e) {
    titanssl_info("[ENGINE][engine_init]\n");

    TEEC_Result r;

    if (!titanssl_teec_context) {
        titanssl_teec_context = calloc(1, sizeof(TEEC_Context));
        if (!titanssl_teec_context) {
            titanssl_error("[ENGINE][engine_init] calloc failed\n");
            return 0;
        }

        r = TEEC_InitializeContext(NULL, titanssl_teec_context);
        if (r != TEEC_SUCCESS) {
            titanssl_error("[ENGINE][engine_init] TEEC_InitializeContext failed: 0x%x\n", r);
            free(titanssl_teec_context);
            titanssl_teec_context = NULL;
            return 0;
        }
    }

    return 1;
}

/* ENGINE cleanup */
int engine_finish(ENGINE *e) {
    titanssl_info("[ENGINE][engine_finish]\n");

    if (titanssl_teec_context) {
        TEEC_FinalizeContext(titanssl_teec_context);
        free(titanssl_teec_context);
        titanssl_teec_context = NULL;
    }

    return 1;
}

/* ENGINE destroy */
int engine_destroy(ENGINE *e) {
    titanssl_info("[ENGINE][engine_destroy]\n");
    return engine_finish(e);
}
/******************************************************************************/
// SHA-256
static int supported_digests[] = {NID_sha256, 0};

int engine_set_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid) {
    if (nids) {
        *nids = supported_digests;
        return 1;
    }

    if (nid != NID_sha256) return 0;

    if (!titanssl_evp_md) {
        titanssl_evp_md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption);
        EVP_MD_meth_set_result_size(titanssl_evp_md, SHA256_DIGEST_LENGTH);
        EVP_MD_meth_set_input_blocksize(titanssl_evp_md, SHA256_CBLOCK);
        EVP_MD_meth_set_app_datasize(titanssl_evp_md, sizeof(TEEC_Session));
        EVP_MD_meth_set_flags(titanssl_evp_md, 0);
        EVP_MD_meth_set_init(titanssl_evp_md, sha256_init);
        EVP_MD_meth_set_update(titanssl_evp_md, sha256_update);
        EVP_MD_meth_set_final(titanssl_evp_md, sha256_final);
        EVP_MD_meth_set_cleanup(titanssl_evp_md, sha256_cleanup);
    }

    *digest = titanssl_evp_md;
    return 1;
}

int sha256_init(EVP_MD_CTX *ctx) {
    titanssl_info("[ENGINE][sha256_init] Initializing SHA-256...\n");

    TEEC_Session *session = (TEEC_Session *)EVP_MD_CTX_md_data(ctx);
    if (!session) {
        titanssl_error("[ENGINE][sha256_init] Error: No TEEC_Session found\n");
        return 0;
    }

    TEEC_Result res = TEEC_OpenSession(titanssl_teec_context, session, NULL, 0, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][sha256_init] TEEC_OpenSession failed (0x%x)\n", res);
        return 0;
    }

    TEEC_Operation op = {0};
    titanssl_parameters_t params = {
        .cmd = TITANSSL_CMD_SHA256_INIT
    };
    uint32_t error;

    op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_TEMP_INPUT,  // [0]: titanssl_parameters_t*
    TEEC_MEMREF_TEMP_INPUT,  // [1]: input buffer (padded)
    TEEC_MEMREF_TEMP_OUTPUT, // [2]: output buffer
    TEEC_NONE
    );

    op.params[0].tmpref.buffer = &params;
    op.params[0].tmpref.size   = sizeof(params);

    res = TEEC_InvokeCommand(session, params.cmd, &op, &error);
    if (res != TEEC_SUCCESS) {
        titanssl_error(
            "[ENGINE][sha256_init] INIT ioctl failed (res=0x%x, err=0x%x)\n",
            res, error
        );
        return 0;
    }

    return 1;
}

int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
    TEEC_Session *session = (TEEC_Session *)EVP_MD_CTX_md_data(ctx);
    if (!session) {
        titanssl_error("[ENGINE][sha256_update] Error: No TEEC_Session found\n");
        return 0;
    }

    TEEC_Operation op = {0};
    titanssl_parameters_t params = {0};

    params.cmd = TITANSSL_CMD_SHA256_UPDATE;
    params.input_address = (uintptr_t)data;
    params.input_size = count;
    params.output_address = 0; 
    params.output_size = 0;
    params.meta_address = 0;  
    params.meta_size = 0;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &params;
    op.params[0].tmpref.size = sizeof(params);

    TEEC_Result result;
    uint32_t error;

    result = TEEC_InvokeCommand(session, params.cmd, &op, &error);
    if (result != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][sha256_update] TEEC_InvokeCommand failed: 0x%x (err=0x%x)\n", result, error);
        return 0;
    }

    return 1;
}


int sha256_final(EVP_MD_CTX *ctx, unsigned char *md) {
    TEEC_Session *session = (TEEC_Session *)EVP_MD_CTX_md_data(ctx);
    if (!session) {
        return 0;
    }

    TEEC_Operation op = {0};
    titanssl_parameters_t params = {0};

    params.cmd = TITANSSL_CMD_SHA256_FINAL;
    params.input_address = 0;  
    params.input_size = 0;
    params.output_address = (uintptr_t)md; 
    params.output_size = SHA256_DIGEST_LENGTH; 
    params.meta_address = 0;  
    params.meta_size = 0;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = &params;
    op.params[0].tmpref.size = sizeof(params);

    TEEC_Result result;
    uint32_t error;

    result = TEEC_InvokeCommand(session, params.cmd, &op, &error);
    if (result != TEEC_SUCCESS) {
        return 0;
    }

    TEEC_CloseSession(session);

    return 1;
}
// clean up SHA256
int sha256_cleanup(EVP_MD_CTX *ctx) {
    return 1;
}
/******************************************************************************/
// AES-256-CBC

static int supported_ciphers[] = { NID_aes_256_cbc, 0 };

int engine_set_cipher(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid) {
    titanssl_info("[ENGINE][engine_set_cipher] Registering AES-256-CBC...\n");

    if (!cipher) {
        *nids = supported_ciphers;
        return 1;
    }

    if (nid != NID_aes_256_cbc) return 0;

    if (!titanssl_evp_cipher) {
        titanssl_evp_cipher = EVP_CIPHER_meth_new(NID_aes_256_cbc, 16, 32);  // block size: 16, key size: 32
        EVP_CIPHER_meth_set_iv_length(titanssl_evp_cipher, 16);
        EVP_CIPHER_meth_set_impl_ctx_size(titanssl_evp_cipher, sizeof(TEEC_Session));
        //EVP_CIPHER_meth_set_flags(titanssl_evp_cipher, EVP_CIPH_CBC_MODE);
        EVP_CIPHER_meth_set_flags(titanssl_evp_cipher, EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1); //use the default ASN.1 padding (Without this flag, OpenSSL assumes your engine will do the padding itself)
        EVP_CIPHER_meth_set_init(titanssl_evp_cipher, aes_init);
        EVP_CIPHER_meth_set_do_cipher(titanssl_evp_cipher, aes_do_cipher);
        EVP_CIPHER_meth_set_cleanup(titanssl_evp_cipher, aes_cleanup);
        EVP_CIPHER_meth_set_ctrl(titanssl_evp_cipher, aes_ctrl);
    }

    *cipher = titanssl_evp_cipher;
    return 1;
}

int aes_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc) {
    titanssl_info("[ENGINE][aes_init] Initializing AES-256-CBC...\n");

    TEEC_Session *session = (TEEC_Session *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!session) {
        titanssl_error("[ENGINE][aes_init] Error: No TEEC_Session found\n");
        return 0;
    }

    TEEC_Result res = TEEC_OpenSession(titanssl_teec_context, session, NULL, 0, NULL, NULL, NULL);
    if (res != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][aes_init] TEEC_OpenSession failed (0x%x)\n", res);
        return 0;
    }

    // Fill session metadata
    titanssl_meta_aes_t *meta = &session->metadata.aes;
    meta->enc = enc;
    memcpy(meta->key_array, key, 32);
    memcpy(meta->iv_array, iv ? iv : key, 16);

    titanssl_parameters_t params = {
        .cmd = TITANSSL_CMD_AES_INIT,
        .meta_address = (uintptr_t)meta,
        .meta_size = sizeof(*meta)
    };

    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    op.params[2].tmpref.buffer = &params;
    op.params[2].tmpref.size = sizeof(params);

    uint32_t error;
    res = TEEC_InvokeCommand(session, TITANSSL_CMD_AES_INIT, &op, &error);
    if (res != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][aes_init] TEEC_InvokeCommand failed RES=0x%x ERR=0x%x\n", res, error);
        return 0;
    }

    return 1;
}



int aes_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) {
    TEEC_Session *session = (TEEC_Session *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!session) {
        titanssl_error("[ENGINE][aes_do_cipher] Error: No TEEC_Session found\n");
        return 0;
    }

    titanssl_parameters_t params = {
        .cmd = TITANSSL_CMD_AES_DOCIPHER,
        .input_address = 0,         
        .input_size = 0,
        .output_address = 0,
        .output_size = 0,
        .meta_address = (uintptr_t)&session->metadata.aes,
        .meta_size = sizeof(titanssl_meta_aes_t)
    };

    TEEC_Operation op = {0};
    op.params[0].tmpref.buffer = (void *)in;
    op.params[0].tmpref.size   = inl;
    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size   = inl;
    op.params[2].tmpref.buffer = &params;
    op.params[2].tmpref.size   = sizeof(params);

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

    uint32_t error;
    TEEC_Result res = TEEC_InvokeCommand(session, TITANSSL_CMD_AES_DOCIPHER, &op, &error);
    if (res != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][aes_do_cipher] TEEC_InvokeCommand failed RES=0x%x ERR=0x%x\n", res, error);
        return 0;
    }

    return 1;
}

int aes_cleanup(EVP_CIPHER_CTX *ctx) {
    titanssl_info("[ENGINE][aes_cleanup] Closing AES session\n");

    TEEC_Session *session = (TEEC_Session *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!session) {
        titanssl_error("[ENGINE][aes_cleanup] Error: No TEEC_Session found\n");
        return 0;
    }

    titanssl_parameters_t params = {
        .cmd = TITANSSL_CMD_AES_CLEANUP
    };

    TEEC_Operation op = {0};
    op.params[2].tmpref.buffer = &params;
    op.params[2].tmpref.size = sizeof(params);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

    uint32_t error;
    TEEC_Result res = TEEC_InvokeCommand(session, TITANSSL_CMD_AES_CLEANUP, &op, &error);
    if (res != TEEC_SUCCESS) {
        titanssl_error("[ENGINE][aes_cleanup] TEEC_InvokeCommand failed RES=0x%x ERR=0x%x\n", res, error);
        return 0;
    }

    TEEC_CloseSession(session);
    return 1;
}

int aes_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
    titanssl_info("[ENGINE][aes_ctrl] Called, type=%d\n", type);
    return 1;
}

/******************************************************************************/
// RSA bind_helper

 int bind_helper_rsa(ENGINE *e, const char *id) {
    titanssl_info("[ENGINE][bind_helper_rsa]\n");

    if (!titanssl_rsa_method) {
        titanssl_rsa_method = RSA_meth_new("TitanSSL RSA Method", 0);
        if (!titanssl_rsa_method) {
            titanssl_error("[ENGINE][bind_helper_rsa] Failed to allocate RSA_METHOD\n");
            return 0;
        }

        RSA_meth_set_flags(titanssl_rsa_method, RSA_METHOD_FLAG_NO_CHECK);

        RSA_meth_set_pub_enc(titanssl_rsa_method, rsa_pub_enc);   // Required for encryption
        RSA_meth_set_pub_dec(titanssl_rsa_method, rsa_pub_dec);   // Required for rsautl -verify
        RSA_meth_set_priv_enc(titanssl_rsa_method, rsa_priv_enc_adapter); // Required for rsautl -sign
        RSA_meth_set_priv_dec(titanssl_rsa_method, rsa_priv_dec); // Required for decryption

        RSA_meth_set_sign(titanssl_rsa_method, titanssl_rsa_sign);     // EVP signing
        RSA_meth_set_verify(titanssl_rsa_method, titanssl_rsa_verify); // EVP verification

        RSA_meth_set_init(titanssl_rsa_method, rsa_init);
        RSA_meth_set_finish(titanssl_rsa_method, rsa_finish);
    }

    if (!ENGINE_set_RSA(e, titanssl_rsa_method)) {
        titanssl_error("[ENGINE][bind_helper_rsa] Failed to set RSA method\n");
        return 0;
    }

    if (!ENGINE_set_load_privkey_function(e, titanssl_load_privkey)) {
        titanssl_error("[ENGINE][bind_helper_rsa] Failed to set privkey loader\n");
        return 0;
    }

    if (!ENGINE_set_load_pubkey_function(e, titanssl_load_pubkey)) {
        titanssl_error("[ENGINE][bind_helper_rsa] Failed to set pubkey loader\n");
        return 0;
    }

    return 1;
}
/******************************************************************************/
// Public Decryption 
int titanssl_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, const RSA *rsa, int padding) {
    return rsa_pub_dec(flen, from, to, (RSA *)rsa, padding);
}

//  Private Encryption 
int titanssl_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, const RSA *rsa, int padding, bool pre_padded) {
    return rsa_priv_enc(flen, from, to, (RSA *)rsa, padding, pre_padded);
}

// Adapter used by OpenSSL hooks (always sets pre_padded=true)
int rsa_priv_enc_adapter(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    return rsa_priv_enc(flen, from, to, rsa, padding, false);
}


/******************************************************************************/
// RSA 

static int rsa_do_tee_op(int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa,
                         int padding, int operation_code) {
    fprintf(stderr, "[ENGINE][rsa_do_tee_op]\n");

    TEEC_Session *session = calloc(1, sizeof(TEEC_Session));
    if (!session)
        return -1;

    if (TEEC_OpenSession(titanssl_teec_context, session,
                         NULL, 0, NULL, NULL, NULL) != TEEC_SUCCESS) {
        free(session);
        return -1;
    }

    titanssl_meta_rsa_t meta;
    memset(&meta, 0, sizeof(meta));

    int ksize = RSA_size(rsa);

    /* --- Case 1: ENGINE-managed key (agnostic path) --- */
    titanssl_rsa_app_data_t *app =
        (titanssl_rsa_app_data_t *)RSA_get_app_data(rsa);

    if (app) {
        fprintf(stderr,
                "[ENGINE][rsa_do_tee_op] ENGINE key: kid=%d, ktype=%s\n",
                app->kid,
                app->ktype == TITANSSL_PKEY_PRIVATE ? "PRIVATE" : "PUBLIC");

        meta.kid       = app->kid;
        meta.ktype     = app->ktype;
        meta.ksize     = ksize;
        meta.input_len = flen;
        meta.operation = operation_code;
        meta.padding   = TITANSSL_PADDING_PKCS1;

    } else {
        /* --- Case 2: PEM key (fallback with DER encode) --- */
        int der_len;
        unsigned char *der_buf = NULL;
        unsigned char *p = NULL;

        if (operation_code == TITANSSL_RSA_OP_PUB_ENC ||
            operation_code == TITANSSL_RSA_OP_PUB_DEC) {
            der_len = i2d_RSAPublicKey(rsa, NULL);
            der_buf = OPENSSL_malloc(der_len);
            p = der_buf;
            i2d_RSAPublicKey(rsa, &p);
            meta.ktype = TITANSSL_PKEY_PUBLIC;
        } else {
            der_len = i2d_RSAPrivateKey(rsa, NULL);
            der_buf = OPENSSL_malloc(der_len);
            p = der_buf;
            i2d_RSAPrivateKey(rsa, &p);
            meta.ktype = TITANSSL_PKEY_PRIVATE;
        }

        if (!der_buf || der_len <= 0 || der_len > sizeof(meta.key_blob)) {
            fprintf(stderr, "[ENGINE][rsa_do_tee_op] DER encode failed/too large\n");
            OPENSSL_free(der_buf);
            TEEC_CloseSession(session);
            free(session);
            return -1;
        }

        memcpy(meta.key_blob, der_buf, der_len);
        meta.blob_len  = der_len;
        meta.ksize     = ksize;
        meta.input_len = flen;
        meta.operation = operation_code;
        meta.padding   = TITANSSL_PADDING_PKCS1;

        OPENSSL_free(der_buf);
    }

    /* Prepare parameters for TA */
    titanssl_parameters_t params = {
        .cmd           = TITANSSL_CMD_RSA_DOCIPHER,
        .input_address = (uintptr_t)from,
        .input_size    = flen,
        .output_address= (uintptr_t)to,
        .output_size   = ksize,
        .meta_address  = (uintptr_t)&meta,
        .meta_size     = sizeof(meta),
    };

    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   // params
        TEEC_MEMREF_TEMP_INPUT,   // input data
        TEEC_MEMREF_TEMP_OUTPUT,  // output buffer
        TEEC_MEMREF_TEMP_INPUT    // metadata
    );

    op.params[0].tmpref.buffer = &params;
    op.params[0].tmpref.size   = sizeof(params);
    op.params[1].tmpref.buffer = (void *)from;
    op.params[1].tmpref.size   = flen;
    op.params[2].tmpref.buffer = to;
    op.params[2].tmpref.size   = ksize;
    op.params[3].tmpref.buffer = &meta;
    op.params[3].tmpref.size   = sizeof(meta);

    fprintf(stderr, "[ENGINE][rsa_do_tee_op] meta.ksize=%u, kid=%d, ktype=%d\n",
            meta.ksize, meta.kid, meta.ktype);

    uint32_t err;
    TEEC_Result result = TEEC_InvokeCommand(session,
                         TITANSSL_CMD_RSA_DOCIPHER, &op, &err);

    int ret = -1;
    if (result == TEEC_SUCCESS) {
        fprintf(stderr, "[ENGINE][rsa_do_tee_op] RSA op succeeded: %d bytes\n",
                meta.ksize);
        print_bytestream(to, meta.ksize);
        ret = meta.ksize;
    } else {
        fprintf(stderr, "[ENGINE][rsa_do_tee_op] RSA op failed: 0x%x\n", result);
    }

    TEEC_CloseSession(session);
    free(session);
    return ret;
}


int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    fprintf(stderr, "[ENGINE][rsa_pub_enc]\n");
    if (!from || !to || !rsa) return -1;

    int ksize = RSA_size(rsa); 

    if (flen > ksize - RSA_PKCS1_PADDING_SIZE) {
        fprintf(stderr, "[ENGINE][rsa_pub_enc] input too long: flen = %d, max = %d\n", flen, ksize - RSA_PKCS1_PADDING_SIZE);
        return -1;
    }

    unsigned char *padded = malloc(ksize);
    if (!padded) return -1;

    if (RSA_padding_add_PKCS1_type_2(padded, ksize, from, flen) <= 0) {
        fprintf(stderr, "[ENGINE][rsa_pub_enc] padding failed\n");
        free(padded);
        return -1;
    }

    //  Allocate separate output buffer
    unsigned char *tmp_output = OPENSSL_malloc(ksize);
    if (!tmp_output) {
        free(padded);
        return -1;
    }

    // Call backend with temp output buffer
    int result = rsa_do_tee_op(ksize, padded, tmp_output, rsa, padding, TITANSSL_RSA_OP_PUB_ENC);
    free(padded);

    if (result > 0) {
        memcpy(to, tmp_output, ksize);
        OPENSSL_free(tmp_output);
        return ksize;
    } else {
        OPENSSL_free(tmp_output);
        return -1;
    }
}


int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
    fprintf(stderr, "[ENGINE][rsa_priv_dec] \n");

    int rsa_len = RSA_size(rsa);  
    unsigned char *tmp = malloc(rsa_len);
    if (!tmp) return -1;

    int ok = rsa_do_tee_op(rsa_len, from, tmp, rsa, padding, TITANSSL_RSA_OP_PRIV_DEC);
    if (ok <= 0) {
        fprintf(stderr, "[ENGINE][rsa_priv_dec] RSA decryption failed\n");
        free(tmp);
        return -1;
    }

    fprintf(stderr, "[ENGINE][rsa_priv_dec] Decrypted raw output (hex):\n");
    print_bytestream(tmp, rsa_len);  

    int len = -1;
    switch (padding) {
        case RSA_PKCS1_PADDING:
            len = RSA_padding_check_PKCS1_type_2(to, rsa_len, tmp, rsa_len, rsa_len);
            break;
        default:
            fprintf(stderr, "[ENGINE][rsa_priv_dec] Unsupported padding: %d\n", padding);
            break;
    }

    free(tmp);
    return (len > 0) ? len : -1;
}

int rsa_priv_enc(int flen, const unsigned char *from,
                 unsigned char *to, RSA *rsa, int padding,
                 bool pre_padded)
{
    titanssl_info("[ENGINE][rsa_priv_enc] Called\n");

    int rsa_len = RSA_size(rsa);
    fprintf(stderr, "[ENGINE][rsa_priv_enc] flen = %d, rsa_len = %d\n", flen, rsa_len);

    if (!pre_padded && flen > rsa_len - 11) {
        titanssl_error("[ENGINE][rsa_priv_enc] ERROR: input too long for key size\n");
        return -1;
    }

    if (padding != RSA_PKCS1_PADDING) {
        titanssl_error("[ENGINE][rsa_priv_enc] ERROR: unsupported padding type\n");
        return -1;
    }

    unsigned char *padded = calloc(1, rsa_len);
    if (!padded) return -1;

    int padlen = -1;

    if (pre_padded) {
        if (flen != rsa_len) {
            titanssl_error("[ENGINE][rsa_priv_enc] ERROR: pre-padded input must match RSA size: flen=%d, rsa_len=%d\n", flen, rsa_len);
            free(padded);
            return -1;
        }
        memcpy(padded, from, flen);
        padlen = flen;
    } else {
        padlen = RSA_padding_add_PKCS1_type_1(padded, rsa_len, from, flen);
        if (padlen <= 0) {
            titanssl_error("[ENGINE][rsa_priv_enc] ERROR: PKCS1_type_1 padding failed\n");
            free(padded);
            return -1;
        }
    }

    
    int ret = rsa_do_tee_op(rsa_len, padded, to, rsa, padding, TITANSSL_RSA_OP_PRIV_ENC);
    free(padded);

    if (ret > 0) {
        fprintf(stderr, "[ENGINE][rsa_priv_enc] SIGNATURE OUTPUT (%d bytes):\n", ret);
        print_bytestream(to, ret);
    } else {
        fprintf(stderr, "[ENGINE][rsa_priv_enc] rsa_do_tee_op failed: ret = %d\n", ret);
    }

    return ret;
}



int rsa_pub_dec(int flen, const unsigned char *from,
                unsigned char *to, RSA *rsa, int padding)
{
    titanssl_info("[ENGINE][rsa_pub_dec] Called\n");

    int rsa_len = RSA_size(rsa);
    if (flen != rsa_len) {
        titanssl_error("[ENGINE][rsa_pub_dec] ERROR: input must match key size\n");
        return -1;
    }

    if (padding != RSA_PKCS1_PADDING) {
        titanssl_error("[ENGINE][rsa_pub_dec] ERROR: unsupported padding type\n");
        return -1;
    }

    // Allocate buffer to hold raw decrypted signature
    unsigned char *raw = calloc(1, rsa_len);
    if (!raw) return -1;

    // Decrypt signature with public key
    int outlen = rsa_do_tee_op(flen, from, raw, rsa, padding, TITANSSL_RSA_OP_PUB_DEC);
    if (outlen <= 0) {
        titanssl_error("[ENGINE][rsa_pub_dec] ERROR: rsa_do_tee_op failed\n");
        free(raw);
        return -1;
    }

    // Strip PKCS#1 v1.5 type 1 padding
    int msglen = RSA_padding_check_PKCS1_type_1(to, rsa_len, raw, outlen, rsa_len);
    if (msglen <= 0) {
        titanssl_error("[ENGINE][rsa_pub_dec] ERROR: RSA_padding_check_PKCS1_type_1 failed\n");
        free(raw);
        return -1;
    }

    free(raw);
    return msglen;
}


/******************************************************************************/
// RSA signing and verification using X509_SIG and ASN.1 digest info
int titanssl_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                      unsigned char *sigret, unsigned int *siglen,
                      const RSA *rsa)
{
    titanssl_info("[ENGINE][titanssl_rsa_sign] Starting RSA sign (PKCS#1 v1.5)\n");

    if (type != NID_sha256 || m_len != 32) {
        titanssl_error("[ENGINE][titanssl_rsa_sign] Unsupported digest type or length\n");
        return 0;
    }

    static const unsigned char digestinfo_prefix[] = {
        0x30, 0x31,
          0x30, 0x0d,
            0x06, 0x09,
              0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00,
          0x04, 0x20
    };

    const int prefix_len = sizeof(digestinfo_prefix);
    const int digestinfo_len = prefix_len + 32;

    unsigned char digestinfo[digestinfo_len];
    memcpy(digestinfo, digestinfo_prefix, prefix_len);
    memcpy(digestinfo + prefix_len, m, 32);

    fprintf(stderr, "[DEBUG][titanssl_rsa_sign] DigestInfo (DER + hash):\n");
    print_bytestream(digestinfo, digestinfo_len);

    int result = rsa_priv_enc(digestinfo_len, digestinfo, sigret, (RSA *)rsa, RSA_PKCS1_PADDING, false);
    if (result <= 0) {
        titanssl_error("[ENGINE][titanssl_rsa_sign] rsa_priv_enc failed\n");
        return 0;
    }

    if (siglen) *siglen = result;
    return 1;
}


int titanssl_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
                        const unsigned char *sigbuf, unsigned int siglen,
                        const RSA *rsa)
{
    titanssl_info("[ENGINE][titanssl_rsa_verify] Verifying X509_SIG signature\n");

    if (type != NID_sha256 || m_len != 32) {
        titanssl_error("[ENGINE][titanssl_rsa_verify] Invalid digest type or length\n");
        return 0;
    }

    unsigned char decrypted[512];
    int len = rsa_pub_dec(siglen, sigbuf, decrypted, (RSA *)rsa, RSA_PKCS1_PADDING);
    if (len <= 0) {
        titanssl_error("[ENGINE][titanssl_rsa_verify] rsa_pub_dec failed\n");
        return 0;
    }

    const unsigned char *p = decrypted;
    X509_SIG *sig = d2i_X509_SIG(NULL, &p, len);
    if (!sig) {
        titanssl_error("[ENGINE][titanssl_rsa_verify] d2i_X509_SIG failed\n");
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL = 1.1.x: use X509_SIG_get0
    const X509_ALGOR *algor = NULL;
    const ASN1_OCTET_STRING *digest = NULL;
    X509_SIG_get0(sig, &algor, &digest);
#else
    // OpenSSL 1.0.x: access struct fields directly
    const X509_ALGOR *algor = sig->algor;
    const ASN1_OCTET_STRING *digest = sig->digest;
#endif

    int digest_nid = OBJ_obj2nid(algor->algorithm);
    if (digest_nid != NID_sha256) {
        titanssl_error("[ENGINE][titanssl_rsa_verify] Unexpected digest NID: %d\n", digest_nid);
        X509_SIG_free(sig);
        return 0;
    }

    if (digest->length != (int)m_len || memcmp(digest->data, m, m_len) != 0) {
        titanssl_error("[ENGINE][titanssl_rsa_verify] Digest mismatch\n");
        X509_SIG_free(sig);
        return 0;
    }

    X509_SIG_free(sig);
    return 1;
}


int rsa_init(RSA *rsa) { return 1; }
int rsa_finish(RSA *rsa) { return 1; }

/******************************************************************************/
// RSA Key Loading
// Backend-agnostic RSA Key Loader for TitanSSL ENGINE
#define DUMMY_KEY_SIZE_BYTES 128  // For 1024-bit keys

EVP_PKEY *load_pkey_helper(ENGINE *e, const char *key_id, titanssl_rsa_ktype_t key_type) {
    fprintf(stderr, "[ENGINE][load_pkey_helper] Loading key: %s | type: %s\n",
            key_id, key_type == TITANSSL_PKEY_PRIVATE ? "PRIVATE" : "PUBLIC");

    RSA *rsa = RSA_new();
    if (!rsa) return NULL;

    // Fake RSA Key Setup 
    unsigned char dummy_buf[DUMMY_KEY_SIZE_BYTES];
    memset(dummy_buf, 0xAA, sizeof(dummy_buf));

    BIGNUM *n = BN_bin2bn(dummy_buf, sizeof(dummy_buf), NULL);
    BIGNUM *e_bn = BN_new(); BN_set_word(e_bn, 65537);
    BIGNUM *d = (key_type == TITANSSL_PKEY_PRIVATE)
              ? BN_bin2bn(dummy_buf, sizeof(dummy_buf), NULL) : NULL;

    RSA_set0_key(rsa, n, e_bn, d);

    if (key_type == TITANSSL_PKEY_PRIVATE) {
        BIGNUM *p = BN_bin2bn(dummy_buf, DUMMY_KEY_SIZE_BYTES / 2, NULL);
        BIGNUM *q = BN_bin2bn(dummy_buf, DUMMY_KEY_SIZE_BYTES / 2, NULL);
        BIGNUM *dmp1 = BN_dup(p);
        BIGNUM *dmq1 = BN_dup(q);
        BIGNUM *iqmp = BN_dup(p);
        RSA_set0_factors(rsa, p, q);
        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
    }

    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK);

    // Attach metadata to RSA 
    titanssl_rsa_app_data_t *meta = OPENSSL_malloc(sizeof(titanssl_rsa_app_data_t));
    if (!meta) {
        RSA_free(rsa);
        return NULL;
    }
    memset(meta, 0, sizeof(*meta));
    meta->kid = (key_type == TITANSSL_PKEY_PRIVATE) ? 1 : 2;
    meta->ktype = key_type;
    meta->ksize = DUMMY_KEY_SIZE_BYTES;

    RSA_set_app_data(rsa, meta);

    //  Wrap RSA in EVP_PKEY and return 
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        OPENSSL_free(meta);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    fprintf(stderr, "[ENGINE][load_pkey_helper] Assigned KID = %d\n", meta->kid);
    fprintf(stderr, "[ENGINE][load_pkey_helper] modulus bits = %d\n", RSA_bits(rsa));
    return pkey;
}



EVP_PKEY *titanssl_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    fprintf(stderr, "[ENGINE][titanssl_load_privkey] key_id: %s\n", key_id);
    fprintf(stderr, "[ENGINE] >>> Called titanssl_load_privkey\n");

    return load_pkey_helper(e, key_id, TITANSSL_PKEY_PRIVATE);
}

EVP_PKEY *titanssl_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    fprintf(stderr, "[ENGINE][titanssl_load_pubkey] key_id: %s\n", key_id);
    fprintf(stderr, "[ENGINE] >>> Called titanssl_load_pubkey\n");

    return load_pkey_helper(e, key_id, TITANSSL_PKEY_PUBLIC);
}



