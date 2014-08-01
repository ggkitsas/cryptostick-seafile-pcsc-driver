#ifndef IMPORT_KEYS_LIB_H
#define IMPORT_KEYS_LIB_H

#include "common.h"

#define SC_OPENPGP_KEYFORMAT_STD    0    /* See 4.3.3.6 Algorithm Attributes */
#define SC_OPENPGP_KEYFORMAT_STDN   1    /* OpenPGP card spec v2 */
#define SC_OPENPGP_KEY_ENCR     2


typedef struct sc_cardctl_openpgp_keygen_info {
    u8 keytype;           /* SC_OPENPGP_KEY_ */          
    u8 *modulus;          /* New-generated pubkey info responded from the card */
    size_t modulus_len;   /* Length of modulus in bit */ 
    u8 *exponent;
    size_t exponent_len;      
} sc_cardctl_openpgp_keygen_info_t;

typedef struct sc_cardctl_openpgp_keystore_info {
    u8 keytype;
    u8 keyformat;
    u8 *e;
    size_t e_len;
    u8 *p;
    size_t p_len;
    u8 *q;
    size_t q_len;
    u8 *n;
    size_t n_len;
    time_t creationtime;
} sc_cardctl_openpgp_keystore_info_t;


/*
typedef struct sc_pkcs15_pubkey sc_pkcs15_pubkey_t;
    
struct sc_pkcs15_prkey {
    unsigned int algorithm;
/* TODO do we need: struct sc_algorithm_id * alg_id; */
/*    
    union {
        struct sc_pkcs15_prkey_rsa rsa;
        struct sc_pkcs15_prkey_dsa dsa;
        struct sc_pkcs15_prkey_ec ec;
        struct sc_pkcs15_prkey_gostr3410 gostr3410;
    } u;
};
*/

int pgp_store_key(card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info);

#endif
