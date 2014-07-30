#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "card.h"
#include "iso7816.h"
#include "openpgp.h"
//#include "asn1.h"

// internal: get features of the card: capabilities, ... 
static int
pgp_get_card_features(card_t *card)
{
    struct pgp_priv_data *priv = DRVDATA (card);
    unsigned char *hist_bytes = card->atr.value;
    size_t atr_len = card->atr.len;
    size_t i = 0;
//    struct blob *blob, *blob6e, *blob73;

    // parse card capabilities from historical bytes 
    while ((i < atr_len) && (hist_bytes[i] != 0x73))
            i++;
    // IS07816-4 hist bytes 3rd function table 
    if ((hist_bytes[i] == 0x73) && (atr_len > i+3)) {
        // bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" 
        if (hist_bytes[i+3] & 0x40) {
            card->caps |= CARD_CAP_APDU_EXT;
            priv->ext_caps = (_ext_caps) ((int)priv->ext_caps | EXT_CAP_APDU_EXT);
        }
        // bit 0x80 in byte 3 of TL 0x73 means "Command chaining"
        if (hist_bytes[i+3] & 0x80)
            priv->ext_caps = (_ext_caps) ((int)priv->ext_caps | EXT_CAP_CHAINING);
    }
//    if (priv->bcd_version >= OPENPGP_CARD_2_0) {
        // get card capabilities from "historical bytes" DO
/*        if ((pgp_get_blob(card, priv->mf, 0x5f52, &blob) >= 0) &&
            (blob->data != NULL) && (blob->data[0] == 0x00)) {
            while ((i < blob->len) && (blob->data[i] != 0x73))
                i++;
            // IS07816-4 hist bytes 3rd function table 
            if ((blob->data[i] == 0x73) && (blob->len > i+3)) {
                /* bit 0x40 in byte 3 of TL 0x73 means "extended Le/Lc" */
/*               if (blob->data[i+3] & 0x40) {
                    card->caps |= CARD_CAP_APDU_EXT;
                    priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_APDU_EXT);
                }
*/
                /* bit 0x80 in byte 3 of TL 0x73 means "Command chaining" */
/*                if (hist_bytes[i+3] & 0x80)
                    priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_CHAINING);
            }

            /* get card status from historical bytes status indicator */
/*            if ((blob->data[0] == 0x00) && (blob->len >= 4))
                priv->state = (_card_state)blob->data[blob->len-3];
        }
//    }

    if ((pgp_get_blob(card, priv->mf, 0x006e, &blob6e) >= 0) &&
        (pgp_get_blob(card, blob6e, 0x0073, &blob73) >= 0)) {

        /* get "extended capabilities" DO */
/*        if ((pgp_get_blob(card, blob73, 0x00c0, &blob) >= 0) &&
            (blob->data != NULL) && (blob->len > 0)) {
            /* in v2.0 bit 0x04 in first byte means "algorithm attributes changeable */
/*            if ((blob->data[0] & 0x04) /*&& (card->type == SC_CARD_TYPE_OPENPGP_V2)*///)
/*                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_ALG_ATTR_CHANGEABLE);
            /* bit 0x08 in first byte means "support for private use DOs" */
/*            if (blob->data[0] & 0x08)
                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_PRIVATE_DO);
            /* bit 0x10 in first byte means "support for CHV status byte changeable" */
/*            if (blob->data[0] & 0x10)
                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_C4_CHANGEABLE);
            /* bit 0x20 in first byte means "support for Key Import" */
/*            if (blob->data[0] & 0x20)
                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_KEY_IMPORT);
            /* bit 0x40 in first byte means "support for Get Challenge" */
/*            if (blob->data[0] & 0x40) {
                card->caps |= SC_CARD_CAP_RNG;
                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_GET_CHALLENGE);
            }
            /* in v2.0 bit 0x80 in first byte means "support Secure Messaging" */
/*            if ((blob->data[0] & 0x80) /*&& (card->type == SC_CARD_TYPE_OPENPGP_V2)*///)
/*                priv->ext_caps = (_ext_caps)((int) priv->ext_caps | EXT_CAP_SM);

            if (/*(priv->bcd_version >= OPENPGP_CARD_2_0) && */ /*(blob->len >= 10)) {
                /* max. challenge size is at bytes 3-4 */
/*                priv->max_challenge_size = bebytes2ushort(blob->data + 2);
                /* max. cert size it at bytes 5-6 */
/*                priv->max_cert_size = bebytes2ushort(blob->data + 4);
                /* max. send/receive sizes are at bytes 7-8 resp. 9-10 */
/*                card->max_send_size = bebytes2ushort(blob->data + 6);
                card->max_recv_size = bebytes2ushort(blob->data + 8);
            }
        }

        /* get max. PIN length from "CHV status bytes" DO */
/*        if ((pgp_get_blob(card, blob73, 0x00c4, &blob) >= 0) &&
            (blob->data != NULL) && (blob->len > 1)) {
            /* 2nd byte in "CHV status bytes" DO means "max. PIN length" */
/*            card->max_pin_len = blob->data[1];
        }

        /* get supported algorithms & key lengths from "algorithm attributes" DOs */
/*        for (i = 0x00c1; i <= 0x00c3; i++) {
            unsigned long flags;

            /* Is this correct? */
            /* OpenPGP card spec 1.1 & 2.0, section 2.1 */
/*            flags = SC_ALGORITHM_RSA_RAW;
            /* OpenPGP card spec 1.1 & 2.0, section 7.2.9 & 7.2.10 */
/*            flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
            flags |= SC_ALGORITHM_RSA_HASH_NONE;
            /* Can be generated in card */
/*            flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

            if ((pgp_get_blob(card, blob73, i, &blob) >= 0) &&
                (blob->data != NULL) && (blob->len >= 4)) {
                if (blob->data[0] == 0x01) {    /* Algorithm ID [RFC4880]: RSA */
/*                    unsigned int keylen = bebytes2ushort(blob->data + 1);  /* Measured in bit */
/*
                    _sc_card_add_rsa_alg(card, keylen, flags, 0);
                }
            }
        }
    }
*/
    return SC_SUCCESS;
}

/* ABI: initialize driver */
int pgp_init(card_t *card)
{
    struct pgp_priv_data *priv;    
    sc_path_t   aid;
    sc_file_t   *file = NULL;
//    struct do_info  *info;
    int r;
    // struct blob     *child = NULL; 

    priv = (pgp_priv_data*)calloc (1, sizeof *priv);
    if (!priv)
        return SC_ERROR_OUT_OF_MEMORY; 
    card->drv_data = priv;

    card->cla = 0x00;

    /* set pointer to correct list of card objects */
//    priv->pgp_objects = pgp2_objects; 

    /* set detailed card version */
//    priv->bcd_version = OPENPGP_CARD_2_0;

    /* select application "OpenPGP" */
    sc_format_path("D276:0001:2401", &aid);
    aid.type = SC_PATH_TYPE_DF_NAME;
    if ((r = iso7816_select_file(card, &aid, &file)) < 0) {
        pgp_finish(card);
        return r;
    }  

    /* read information from AID */
    if (file && file->namelen == 16) {
        /* OpenPGP card spec 1.1 & 2.0, section 4.2.1 & 4.1.2.1 */
        priv->bcd_version = (_version)bebytes2ushort(file->name + 6);
        /* kludge: get card's serial number from manufacturer ID + serial number */
        memcpy(card->serialnr.value, file->name + 8, 6);
        card->serialnr.len = 6;        
    }  

    /* change file path to MF for re-use in MF */
//    sc_format_path("3f00", &file->path);

    /* set up the root of our fake file tree */
/*    priv->mf = pgp_new_blob(card, NULL, 0x3f00, file);
    if (!priv->mf) {
        pgp_finish(card);
        return SC_ERROR_OUT_OF_MEMORY; 
    }  
*/
    /* select MF */
//    priv->current = priv->mf;

    /* Populate MF - add matching blobs listed in the pgp_objects table. */
/*    for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
        if (((info->access & READ_MASK) == READ_ALWAYS) &&
            (info->get_fn != NULL)) {      
            child = pgp_new_blob(card, priv->mf, info->id, sc_file_new());

            /* catch out of memory condition */
/*            if (child == NULL) {               
                pgp_finish(card);              
                return SC_ERROR_OUT_OF_MEMORY;                                                                                                                                                                                         
            }
        }
    }  
*/
    /* get card_features from ATR & DOs */
    pgp_get_card_features(card);

    card->flags = CARD_CAP_APDU_EXT;

    return SC_SUCCESS;
}

/* ABI: GET DATA */
int pgp_get_data(card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
    apdu_t   apdu;
    int     r;

    format_apdu(card, &apdu, APDU_CASE_2, 0xCA, tag >> 8, tag);
    apdu.le = ((buf_len >= 256) && !(card->caps & CARD_CAP_APDU_EXT)) ? 256 : buf_len;
    apdu.resp = buf;
    apdu.resplen = buf_len;

    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");                                                                                                                                                                                 

    LOG_FUNC_RETURN(apdu.resplen);                                                                                                                                                                                          
}

int pgp_finish(card_t *card)
{
    if (card != NULL) {
        struct pgp_priv_data *priv = DRVDATA (card);

        if (priv != NULL) {
            /* delete private data */      
            free(priv);
        }
        card->drv_data = NULL;
    }  
    return SC_SUCCESS;
}

/* ABI: PIN cmd: verify/change/unblock a PIN */                                                                                                                                                                                        
int pgp_pin_cmd(card_t *card, struct sc_pin_cmd_data *data, int *tries_left)                                                                                                                                                            
{
//    if (data->pin_type != SC_AC_CHV)   
//        LOG_TEST_RET(SC_ERROR_INVALID_ARGUMENTS,"invalid PIN type");                                                                                                                                                                                                   

    /* In general, the PIN Reference is extracted from the key-id, for
     * example, CHV0 -> Ref=0, CHV1 -> Ref=1.
     * However, in the case of OpenGPG, the PIN Ref to compose APDU                                                                                                                                                                    
     * must be 81, 82, 83.
     * So, if we receive Ref=1, Ref=2, we must convert to 81, 82...
     * In OpenPGP ver 1, the PINs are named CHV1, CHV2, CHV3. In ver 2, they
     * are named PW1, PW3 (PW1 operates in 2 modes). However, the PIN references (P2 in APDU)                                                                                                                                          
     * are the same between 2 version:
     * 81 (CHV1 or PW1), 82 (CHV2 or PW1-mode 2), 83 (CHV3 or PW3).                                                                                                                                                                    
     * 
     * Note that if this function is called from sc_pkcs15_verify_pin() in pkcs15-pin.c,                                                                                                                                               
     * the Ref is already 81, 82, 83.
    */

    /* Convert the PIN Reference if needed */
    data->pin_reference |= 0x80;   
    /* Ensure pin_reference is 81, 82, 83 */
    if (!(data->pin_reference == 0x81 || data->pin_reference == 0x82 || data->pin_reference == 0x83)) {                                                                                                                                
        LOG_TEST_RET(SC_ERROR_INVALID_ARGUMENTS, "key-id should be 1, 2, 3.");                                                                                                                                                                                     
    }
    LOG_FUNC_RETURN(iso7816_pin_cmd(card, data, tries_left));                                                                                                                                                              
}

/* internal: get public key from card: as DF + sub-wEFs */                                                                                                                                       
static int
pgp_get_pubkey(card_t *card, unsigned int tag, u8 *buf, size_t buf_len)                                                                                                                       
{
    apdu_t   apdu;
    u8      idbuf[2];
    int     r;

    printf("called, tag=%04x\n", tag);                                                                                                                                                

    format_apdu(card, &apdu, APDU_CASE_4, 0x47, 0x81, 0);                                                                                                                                  
    apdu.lc = 2;
    apdu.data = ushort2bebytes(idbuf, tag);
    apdu.datalen = 2;
    apdu.le = ((buf_len >= 256) && !(card->caps & SC_CARD_CAP_APDU_EXT)) ? 256 : buf_len;                                                                                                        
    apdu.resp = buf;          
    apdu.resplen = buf_len;

    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET(r, "APDU transmit failed");                                                                                                                                          

    r = check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(r, "Card returned error");                                                                                                                                           

    LOG_FUNC_RETURN(apdu.resplen);                                                                                                                                                    
}
