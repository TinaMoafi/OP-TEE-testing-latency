/* tee_client_api_wrapper.h */
#ifndef TEE_CLIENT_API_WRAPPER_H
#define TEE_CLIENT_API_WRAPPER_H

#include <tee_client_api.h>

/* ---------- Wrapper API (implemented in tee_client_api.c) ---------- */
TEEC_Result TitanSSL_TEEC_InitializeContext(const char *name, TEEC_Context *context);
void        TitanSSL_TEEC_FinalizeContext(TEEC_Context *context);
TEEC_Result TitanSSL_TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
                                      const TEEC_UUID *destination,
                                      uint32_t connectionMethod,
                                      const void *connectionData,
                                      TEEC_Operation *operation,
                                      uint32_t *returnOrigin);
void        TitanSSL_TEEC_CloseSession(TEEC_Session *session);
TEEC_Result TitanSSL_TEEC_InvokeCommand(TEEC_Session *session,
                                        uint32_t commandID,
                                        TEEC_Operation *operation,
                                        uint32_t *returnOrigin);

/* ---------- Macro remapping for the ENGINE code ----------
 * When compiling the engine (no TITANSSL_WRAPPER_INTERNAL), redirect
 * TEEC_* calls to our wrapper functions. When compiling the wrapper
 * itself (TITANSSL_WRAPPER_INTERNAL is defined), do NOT remap, so the
 * wrapper can call the real libteec symbols.
 */
#ifndef TITANSSL_WRAPPER_INTERNAL
#  define TEEC_InitializeContext TitanSSL_TEEC_InitializeContext
#  define TEEC_FinalizeContext   TitanSSL_TEEC_FinalizeContext
#  define TEEC_OpenSession       TitanSSL_TEEC_OpenSession
#  define TEEC_CloseSession      TitanSSL_TEEC_CloseSession
#  define TEEC_InvokeCommand     TitanSSL_TEEC_InvokeCommand
#endif

#endif /* TEE_CLIENT_API_WRAPPER_H */
