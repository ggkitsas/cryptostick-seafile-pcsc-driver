#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "openssl/sha.h"

#include "common.h"
#include "asn1.h"
#include "openpgp.h"
#include "import_keys_lib.h"


/**
 *  * Internal: Update pubkey blob.
 *   * Note that modulus_len, exponent_len is measured in bit.
 *    **/
/*
static int
pgp_update_pubkey_blob(card_t *card, u8* modulus, size_t modulus_len,
                       u8* exponent, size_t exponent_len, u8 key_id)
{
    struct pgp_priv_data *priv = DRVDATA(card);
    struct blob *pk_blob;
    unsigned int blob_id;
    sc_pkcs15_pubkey_t pubkey;
    u8 *data = NULL;
    size_t len;
    int r;

    if (key_id == SC_OPENPGP_KEY_SIGN)
        blob_id = 0xB601;
    else if (key_id == SC_OPENPGP_KEY_ENCR)
        blob_id = 0xB801;
    else if (key_id == SC_OPENPGP_KEY_AUTH)
        blob_id = 0xA401;
    else {
        printf( "Unknown key id %X.\n", key_id);
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }

    printf( "Get the blob %X.\n", blob_id);
    r = pgp_get_blob(card, priv->mf, blob_id, &pk_blob);
    LOG_TEST_RET( r, "Cannot get the blob.");

    /* Encode pubkey */
/*    memset(&pubkey, 0, sizeof(pubkey));
    pubkey.algorithm = SC_ALGORITHM_RSA;
    pubkey.u.rsa.modulus.data  = modulus;
    pubkey.u.rsa.modulus.len   = modulus_len >> 3;  /* 1/8 */
/*    pubkey.u.rsa.exponent.data = exponent;
    pubkey.u.rsa.exponent.len  = exponent_len >> 3;

    r = sc_pkcs15_encode_pubkey( &pubkey, &data, &len);

    printf( "Update blob content.\n");
    r = pgp_set_blob(pk_blob, data, len);
    LOG_TEST_RET( r, "Cannot update blob content.\n");
    LOG_FUNC_RETURN( r);
}
*/

/**
 *  * Internal: Calculate PGP fingerprints.
 *   * Reference: GnuPG, app-openpgp.c.
 *    * modulus and exponent are passed separately from key_info
 *     * because key_info->exponent may be null.
 *      **/
static int
pgp_calculate_and_store_fingerprint(card_t *card, time_t ctime,
                                    u8* modulus, u8* exponent,
                                    sc_cardctl_openpgp_keygen_info_t *key_info)
{
    u8 fingerprint[SHA_DIGEST_LENGTH];
    size_t mlen = key_info->modulus_len >> 3;  /* 1/8 */
    size_t elen = key_info->exponent_len >> 3;  /* 1/8 */
    u8 *fp_buffer = NULL;  /* Fingerprint buffer, not hashed */
    size_t fp_buffer_len;
    u8 *p; /* Use this pointer to set fp_buffer content */
    size_t pk_packet_len;
    unsigned int tag;
    struct blob *fpseq_blob;
    u8 *newdata;
    int r;

    if (modulus == NULL || exponent == NULL || mlen == 0 || elen == 0) {
        printf("Null data (modulus or exponent)\n");
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }

    /* http://tools.ietf.org/html/rfc4880  page 41, 72 */
    pk_packet_len =   1   /* For ver number */
                    + 4   /* Creation time */
                    + 1   /* Algorithm */
                    + 2   /* Algorithm-specific fields */
                    + mlen
                    + 2
                    + elen;

    fp_buffer_len = 3 + pk_packet_len;
    p = fp_buffer = (u8*)calloc(fp_buffer_len, 1);
    if (!p) {
        LOG_FUNC_RETURN( SC_ERROR_NOT_ENOUGH_MEMORY);
    }

    p[0] = 0x99;   /* http://tools.ietf.org/html/rfc4880  page 71 */
    ushort2bebytes(++p, pk_packet_len);
    /* Start pk_packet */
    p += 2;
    *p = 4;        /* Version 4 key */
    ulong2bebytes(++p, ctime);    /* Creation time */
    p += 4;
    *p = 1;        /* RSA */
    /* Algorithm-specific fields */
    ushort2bebytes(++p, key_info->modulus_len);
    p += 2;
    memcpy(p, modulus, mlen);
    p += mlen;
    ushort2bebytes(++p, key_info->exponent_len);
    p += 2;
    memcpy(p, exponent, elen);
    p = NULL;

    /* Hash with SHA-1 */
    SHA1(fp_buffer, fp_buffer_len, fingerprint);
    free(fp_buffer);

    /* Store to DO */
    tag = 0x00C6 + key_info->keytype;
    printf( "Write to DO %04X.\n", tag);
    r = pgp_put_data(card, 0x00C6 + key_info->keytype, fingerprint, SHA_DIGEST_LENGTH);
    LOG_TEST_RET( r, "Cannot write to DO.");

    /* Update the blob containing fingerprints (00C5) */
    printf( "Update the blob containing fingerprints (00C5)\n");
    fpseq_blob = pgp_find_blob(card, 0x00C5);
    if (!fpseq_blob) {
        printf( "Not found 00C5\n");
        goto exit;
    }
    /* Save the fingerprints sequence */
    newdata = (u8*)malloc(fpseq_blob->len);
    if (!newdata) {
        printf( "Not enough memory to update fingerprints blob.\n");
        goto exit;
    }
    memcpy(newdata, fpseq_blob->data, fpseq_blob->len);
    /* Move p to the portion holding the fingerprint of the current key */
    p = newdata + 20*(key_info->keytype - 1);
    /* Copy new fingerprint value */
    memcpy(p, fingerprint, 20);
    /* Set blob's data */
    pgp_set_blob(fpseq_blob, newdata, fpseq_blob->len);
    free(newdata);

exit:
    LOG_FUNC_RETURN( r);
}

/**    
 *  * Internal: Store creation time of key.
 *   * Pass non-zero outtime to use predefined time.
 *    * Pass zero/null outtime to calculate current time. outtime then will be output.
 *     * Pass null outtime to not receive output.
 *      **/   
static int pgp_store_creationtime(card_t *card, u8 key_id, time_t *outtime)
{
    int r;
    time_t createtime = 0;    
    const size_t timestrlen = 64;  
    char timestring[65];      
    u8 buf[4];

    if (key_id == 0 || key_id > 3) {
        printf("Invalid key ID %d.\n", key_id); 
        LOG_FUNC_RETURN(SC_ERROR_INVALID_DATA);
    }  

    if (outtime != NULL && *outtime != 0)
        createtime = *outtime;
    else if (outtime != NULL) 
        /* Set output */      
        *outtime = createtime = time(NULL);

    strftime(timestring, timestrlen, "%c %Z", gmtime(&createtime)); 
    printf("Creation time %s.\n", timestring);
    /* Code borrowed from GnuPG */ 
    ulong2bebytes(buf, createtime);
    r = pgp_put_data(card, 0x00CD + key_id, buf, 4);
    LOG_TEST_RET(r, "Cannot write to DO");
    LOG_FUNC_RETURN( r); 
}

/**
 *  * Internal: Build TLV.
 *   * @param[in]  data   The data ("value") part to build TLV.
 *    * @param[in]  len    Data length
 *     * @param[out] out    The buffer of overall TLV. This buffer should be freed later.
 *      * @param[out] outlen The length of buffer out.
 *       **/
static int
pgp_build_tlv(unsigned int tag, u8 *data, size_t len, u8 **out, size_t *outlen)
{
    u8 highest_order = 0;
    u8 cla;
    int r;
    r = asn1_write_element(tag, data, len, out, outlen);
    LOG_TEST_RET(r, "Failed to write ASN.1 element");
    /* Restore class bits stripped by sc_asn1_write_element */
    /* Determine the left most byte of tag, which contains class bits */
    while (tag >> 8*highest_order) {
        highest_order++;
    }
    highest_order--;
    cla = tag >> 8*highest_order;
    /* Restore class bits */
    *out[0] |= cla;
    return SC_SUCCESS;
}

/**
 *  * Internal: Set Tag & Length components for TLV, store them in buffer.
 *   * Return the total length of Tag + Length.
 *    * Note that the Value components is not counted.
 *     * Ref: add_tlv() of GnuPG code.
 *      **/
static size_t
set_taglength_tlv(u8 *buffer, unsigned int tag, size_t length)
{
    u8 *p = buffer;

    assert(tag <= 0xffff);
    if (tag > 0xff)
        *p++ = (tag >> 8) & 0xFF;
    *p++ = tag;
    if (length < 128)
        *p++ = length;
    else if (length < 256) {
        *p++ = 0x81;
        *p++ = length;
    }
    else {
        if (length > 0xffff)
            length = 0xffff;
        *p++ = 0x82;
        *p++ = (length >> 8) & 0xFF;
        *p++ = length & 0xFF;
    }

    return p - buffer;
}

/*
 * Internal: Build Extended Header list (sec 4.3.3.7 - OpenPGP card spec v.2)                                                                                                                                                          
 */
static int
pgp_build_extended_header_list(card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info,                                                                                                                                          
                               u8 **result, size_t *resultlen)                                                                                                                                                                         
{
    /* The Cardholder private key template (7F48) part */
    const size_t max_prtem_len = 7*(1 + 3);     /* 7 components */             
                                                /* 1 for tag name (91, 92... 97)
                                                 * 3 for storing length */                                                                                                                                                             
    u8 pritemplate[7*(1 + 3)];
    size_t tpl_len = 0;     /* Actual size of pritemplate */
    /* Concatenation of key data */
    u8 kdata[3 + 256 + 256 + 512];  /* Exponent is stored in 3 bytes
                                     * With maximum 4096-bit key,
                                     * p and q can be stored in 256 bytes (2048 bits).
                                     * Maximum 4096-bit modulus is stored in 512 bytes */                                                                                                                                              
    size_t kdata_len = 0;   /* Actual size of kdata */
    u8 *tlvblock = NULL;      
    size_t tlvlen = 0;        
    u8 *tlv_5f48 = NULL;      
    size_t tlvlen_5f48 = 0;   
    u8 *tlv_7f48 = NULL;      
    size_t tlvlen_7f48 = 0;   
    u8 *data = NULL;
    size_t len = 0;           
    u8 *p = NULL;
    u8 *components[] = {key_info->e, key_info->p, key_info->q, key_info->n};
    size_t componentlens[] = {key_info->e_len, key_info->p_len, key_info->q_len, key_info->n_len};                                                                                                                                     
    unsigned int componenttags[] = {0x91, 0x92, 0x93, 0x95};
    const char *componentnames[] = {
        "public exponent",    
        "prime p",
        "prime q",
        "modulus"
    }; 
    size_t comp_to_add = 3;   
    size_t req_e_len = 0;     /* The exponent length specified in Algorithm Attributes */                                                                                                                                              
    struct blob *alat_blob;   
    u8 i;
    int r;

    if (key_info->keyformat == SC_OPENPGP_KEYFORMAT_STDN
        /*|| key_info->keyformat == SC_OPENPGP_KEYFORMAT_CRTN*/)
        comp_to_add = 4;      

    /* Validate */            
    if (comp_to_add == 4 && (key_info->n == NULL || key_info->n_len == 0)){
        printf("Error: Modulus required!\n");
        LOG_FUNC_RETURN(SC_ERROR_INVALID_ARGUMENTS);                                                                                                                                                                              
    }  

    /* Cardholder private key template's data part */
    memset(pritemplate, 0, max_prtem_len);                                                                                                                                                                                             

printf("CHECKPOINT 2.1\n");
    /* Get required exponent length */
    alat_blob = pgp_find_blob(card, 0x00C0 | key_info->keytype);                                                                                                                                                                       
printf("CHECKPOINT 2.2\n");
    if (!alat_blob) {         
        printf("Cannot read Algorithm Attributes\n.");
        LOG_FUNC_RETURN(SC_ERROR_OBJECT_NOT_FOUND);                                                                                                                                                                               
    }
    req_e_len = bebytes2ushort(alat_blob->data + 3) >> 3;   /* 1/8 */

    /* We need to right justify the exponent with required length, for example,
 *      * from 01 00 01 to 00 01 00 01 */
    if (key_info->e_len < req_e_len) {
        /* Create new buffer */
        p = (u8*)calloc(req_e_len, 1);
        memcpy(p + req_e_len - key_info->e_len, key_info->e, key_info->e_len);
        key_info->e_len = req_e_len;
        /* Set key_info->e to new buffer */
        free(key_info->e);
        key_info->e = p;
        components[0] = p;
        componentlens[0] = req_e_len;
    }

    /* Start from beginning of pritemplate */
    p = pritemplate;

    for (i = 0; i < comp_to_add; i++) {
        printf("Set Tag+Length for %s (%X).\n", componentnames[i], componenttags[i]);
        len = set_taglength_tlv(p, componenttags[i], componentlens[i]);
        tpl_len += len;

        /*
         *       <-- kdata_len --><--  Copy here  -->
         * kdata |===============|___________________
         */
        memcpy(kdata + kdata_len, components[i], componentlens[i]);
        kdata_len += componentlens[i];

        /* Move p to next part and build */
        p += len;
    }

    /* TODO: Components for CRT format */

    /* TLV block for 7F48 */
    r = pgp_build_tlv(0x7F48, pritemplate, tpl_len, &tlv_7f48, &tlvlen_7f48);
    LOG_TEST_RET(r, "Failed to build TLV for 7F48.");
    tlv_7f48[0] |= 0x7F;
    r = pgp_build_tlv(0x5f48, kdata, kdata_len, &tlv_5f48, &tlvlen_5f48);
    LOG_TEST_RET(r, "Failed to build TLV for 5F48.");

    /* Data part's length for Extended Header list */
    len = 2 + tlvlen_7f48 + tlvlen_5f48;
    /* Set data part content */
    data = (u8*)calloc(len, 1);
    if (data == NULL) {
        printf("Not enough memory.\n");
        r = SC_ERROR_NOT_ENOUGH_MEMORY;
        goto out2;
    }
/*    switch (key_info->keytype) {
    case SC_OPENPGP_KEY_SIGN:
        data[0] = 0xB6;
        break;
    case SC_OPENPGP_KEY_ENCR:
*/
        data[0] = 0xB8;
/*        break;
    case SC_OPENPGP_KEY_AUTH:
        data[0] = 0xA4;
        break;
    default:
        printf("Unknown key type %d.", key_info->keytype);
        r = SC_ERROR_INVALID_ARGUMENTS;
        goto out1;
    }
*/

    memcpy(data + 2, tlv_7f48, tlvlen_7f48);
    memcpy(data + 2 + tlvlen_7f48, tlv_5f48, tlvlen_5f48);
    r = pgp_build_tlv(0x4D, data, len, &tlvblock, &tlvlen);
    if (r < 0) {
        printf("Cannot build TLV for Extended Header list.\n");
        goto out1;
    }
    /* Set output */
    if (result != NULL) {
        *result = tlvblock;
        *resultlen = tlvlen;
    } else {
        free(tlvblock);
    }

out1:
    free(data);

out2:
    free(tlv_7f48);
    free(tlv_5f48);
    LOG_FUNC_RETURN(r);
}


int pgp_store_key(card_t *card, sc_cardctl_openpgp_keystore_info_t *key_info)
{
    sc_cardctl_openpgp_keygen_info_t pubkey;
    u8 *data;
    size_t len;
    int r=0;

    /* Validate */
//    if (key_info->keytype < 1 || key_info->keytype > 3) {
    if (key_info->keytype != 2) {
        printf("Unknown key type %d.\n", key_info->keytype);
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }  
printf("CHECKPOINT 1\n");
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
        printf("Exponent %lubit (>32) is not supported.\n", key_info->e_len*8);
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

printf("CHECKPOINT 2\n");
//    r = pgp_update_new_algo_attr(card, &pubkey);
    LOG_TEST_RET( r, "Failed to update new algorithm attributes");

    /* Build Extended Header list */
    r = pgp_build_extended_header_list(card, key_info, &data, &len);
    if (r < 0) {
        printf("Failed to build Extended Header list.\n");
        goto out;
    }
printf("CHECKPOINT 3\n");
    /* Write to DO */
    r = pgp_put_data(card, 0x4D, data, len);
    if (r < 0) {
        printf("Failed to write to DO.\n");
        goto out;
    }

printf("CHECKPOINT 4\n");
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
//    r = pgp_update_pubkey_blob(card, key_info->n, 8*key_info->n_len,
//                               key_info->e, 8*key_info->e_len, key_info->keytype);

    printf("Update card algorithms.\n");
//    pgp_update_card_algorithms(card, &pubkey);

out:
    if (data) {
        free(data);
        data = NULL;
    }
    LOG_FUNC_RETURN(r);
}
