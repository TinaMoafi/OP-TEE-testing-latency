#ifndef TITANSSL_H
#define TITANSSL_H


/*padding */
#define TITANSSL_PADDING_NONE  0
#define TITANSSL_PADDING_PKCS1 1

/* RSA Key Limits and Custom ID */
#define TITANSSL_RSA_KEY_MAXLEN 512
#define TITANSSL_PKEY_KID_CUSTOM 0

// RSA operation codes
#define TITANSSL_RSA_OP_PUB_ENC   0  // Public Encrypt (Privacy)
#define TITANSSL_RSA_OP_PRIV_DEC  1  // Private Decrypt (Privacy)
#define TITANSSL_RSA_OP_PUB_DEC   2  // Public Decrypt (Authentication)
#define TITANSSL_RSA_OP_PRIV_ENC  3  // Private Encrypt (Authentication)



/* TitanSSL Command Enum */
typedef enum {
    TITANSSL_CMD_SHA256_INIT,
    TITANSSL_CMD_SHA256_UPDATE,
    TITANSSL_CMD_SHA256_FINAL,
    TITANSSL_CMD_AES_INIT,
    TITANSSL_CMD_AES_DOCIPHER,
    TITANSSL_CMD_AES_CLEANUP,
    TITANSSL_CMD_RSA_DOCIPHER   
} titanssl_command_t;

/* TitanSSL Operation Parameters (Used in IOCTL/TEE) */
typedef struct titanssl_parameters_t {
    unsigned long cmd;            /* Command type (SHA, AES, RSA) */
    unsigned long input_size;     /* Input buffer size */
    unsigned long input_address;  /* Input buffer address */
    unsigned long output_size;    /* Output buffer size */
    unsigned long output_address; /* Output buffer address */
    unsigned long meta_size;      /* Metadata size */
    unsigned long meta_address;   /* Metadata address */
    unsigned long session_id;     /* Session ID */
    unsigned long session_cnt;    /* Session Counter */
} titanssl_parameters_t;

/* TitanSSL Mailbox Header (Low-level ABI) */
typedef struct __attribute__((__packed__)) titanssl_mbox_header_t {
    unsigned int magic_number;  /* Always TITANSSL_MAGIC_NUMBER */

    unsigned int input_dsz;     /* Input total size */
    unsigned int input_nop;     /* Number of pages */
    unsigned int input_fpo;     /* First page offset */
    unsigned int input_fps;     /* First page size */
    unsigned int input_lps;     /* Last page size */
    unsigned int input_map;     /* Master page address */

    unsigned int output_dsz;    /* Output total size */
    unsigned int output_nop;
    unsigned int output_fpo;
    unsigned int output_fps;
    unsigned int output_lps;
    unsigned int output_map;

    unsigned int meta_dsz;      /* Metadata total size */
    unsigned int meta_nop;
    unsigned int meta_fpo;
    unsigned int meta_fps;
    unsigned int meta_lps;
    unsigned int meta_map;
} titanssl_mbox_header_t;

//* AES Metadata Structure */
typedef struct {
    unsigned int enc;
    unsigned char iv_array[16];   // 128-bit IV
    unsigned char key_array[32];  // 256-bit key
} titanssl_meta_aes_t;


#endif