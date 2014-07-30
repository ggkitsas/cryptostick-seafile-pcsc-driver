#include "import_keys_lib.h"

static int pgp_store_key(card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info)
{
    sc_cardctl_openpgp_keygen_info_t pubkey;
    u8 *data;
    size_t len;
    int r;

    /* Validate */
    if (key_info->keytype < 1 || key_info->keytype > 3) {
        printf("Unknown key type %d.\n", key_info->keytype);
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }  
    /* We just support standard key format */
    switch (key_info->keyformat) { 
    case SC_OPENPGP_KEYFORMAT_STD: 
    case SC_OPENPGP_KEYFORMAT_STDN:
        break;

    default:
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }  

    /* We only support exponent of maximum 32 bits */
    if (key_info->e_len > 4) {
        printf("Exponent %bit (>32) is not supported.\n", key_info->e_len*8);
        LOG_FUNC_RETURN( SC_ERROR_NOT_SUPPORTED);
    }  

    /* Set algorithm attributes */ 
    memset(&pubkey, 0, sizeof(pubkey));
    pubkey.keytype = key_info->keytype;
    if (key_info->n && key_info->n_len) {
        pubkey.modulus = key_info->n;  
        pubkey.modulus_len = 8*key_info->n_len;
        /* We won't update exponent length, because smaller exponent length
 *          * will be padded later */
    }  
    r = pgp_update_new_algo_attr(card, &pubkey);
    LOG_TEST_RET( r, "Failed to update new algorithm attributes");
    /* Build Extended Header list */
    r = pgp_build_extended_header_list(card, key_info, &data, &len);
    if (r < 0) {
        printf("Failed to build Extended Header list.\n");
        goto out;
    }
    /* Write to DO */
    r = pgp_put_data(card, 0x4D, data, len);
    if (r < 0) {
        printf("Failed to write to DO.\n");
        goto out;
    }

    free(data);
    data = NULL;

    /* Store creation time */
    r = pgp_store_creationtime(card, key_info->keytype, &key_info->creationtime);
    LOG_TEST_RET(r, "Cannot store creation time");

    /* Calculate and store fingerprint */
    printf("Calculate and store fingerprint\n");
    r = pgp_calculate_and_store_fingerprint(card, key_info->creationtime, key_info->n, key_info->e, &pubkey);
    LOG_TEST_RET( r, "Cannot store fingerprint.\n");
    /* Update pubkey blobs (B601,B801, A401) */
    printf("Update blobs holding pubkey info.\n");
    r = pgp_update_pubkey_blob(card, key_info->n, 8*key_info->n_len,
                               key_info->e, 8*key_info->e_len, key_info->keytype);

    printf("Update card algorithms.\n");
    pgp_update_card_algorithms(card, &pubkey);

out:
    if (data) {
        free(data);
        data = NULL;
    }
    LOG_FUNC_RETURN(r);
}
