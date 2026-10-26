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
#include "titanssl.h"
#include "titanssl_common.h"



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


/******************************************************************************/
// Globals
static TEEC_Context *titanssl_teec_context = NULL;
static EVP_MD *titanssl_evp_md = NULL;
static EVP_CIPHER *titanssl_evp_cipher = NULL;

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
	fprintf(stderr, "[ENGINE] impl_ctx_size=%zu\n", sizeof(TEEC_Session));

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
