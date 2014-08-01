#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "card.h"
#include "iso7816.h"
#include "openpgp.h"
//#include "asn1.h"

static int
pgp_get_pubkey(card_t *card, unsigned int tag, u8 *buf, size_t buf_len);


#ifdef __cplusplus
extern "C" {
#endif

static struct do_info       pgp2_objects[] = {  /* OpenPGP card spec 2.0 */
    { 0x004d, (_type)CONSTRUCTED, (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x004f, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_data,        NULL        },
    { 0x005b, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x005e, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x0065, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_data,        NULL        },
    { 0x006e, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_data,        NULL        },
    { 0x0073, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x007a, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_data,        NULL        },
    { 0x0081, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x0082, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x0093, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x00c0, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x00c1, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c2, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c3, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c4, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x00c5, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c6, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c7, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c8, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00c9, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00ca, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00cb, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00cc, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00cd, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00ce, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00cf, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00d0, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00d1, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00d2, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00d3, (_type)SIMPLE,      (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x00f4, (_type)CONSTRUCTED, (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x0101, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN2),  pgp_get_data,        pgp_put_data },
    { 0x0102, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x0103, (_type)SIMPLE,      (_access)(READ_PIN2   | WRITE_PIN2),  pgp_get_data,        pgp_put_data },
    { 0x0104, (_type)SIMPLE,      (_access)(READ_PIN3   | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x3f00, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0x5f2d, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x5f35, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x5f48, (_type)CONSTRUCTED, (_access)(READ_NEVER  | WRITE_PIN3),  NULL,               pgp_put_data },
    { 0x5f50, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x5f52, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_data,        NULL        },
    /* The 7F21 is constructed DO in spec, but in practice, its content can be retrieved                                                                                                                                               
 *      * as simple DO (no need to parse TLV). */
    { 0x7f21, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3),  pgp_get_data,        pgp_put_data },
    { 0x7f48, (_type)CONSTRUCTED, (_access)(READ_NEVER  | WRITE_NEVER), NULL,               NULL        },
    { 0x7f49, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), NULL,               NULL        },
    { 0xa400, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER), pgp_get_pubkey,     NULL        },
    /* The 0xA401, 0xB601, 0xB801 are just symbolic, it does not represent any real DO.
 *      * However, their R/W access condition may block the process of importing key in pkcs15init.
 *           * So we set their accesses condition as WRITE_PIN3 (writable). */
    { 0xa401, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3), pgp_get_pubkey/*_pem*/, NULL        },
    { 0xb600, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER),  pgp_get_pubkey,     NULL        },
    { 0xb601, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3), pgp_get_pubkey/*_pem*/, NULL        },
    { 0xb800, (_type)CONSTRUCTED, (_access)(READ_ALWAYS | WRITE_NEVER),  pgp_get_pubkey,     NULL        },
    { 0xb801, (_type)SIMPLE,      (_access)(READ_ALWAYS | WRITE_PIN3), pgp_get_pubkey/*_pem*/, NULL        },                                                                                                                                                
    { 0, 0, 0, NULL, NULL },  
};

#ifdef __cplusplus
}
#endif

#define DO_CERT     0x7f21

/*
sc_file_t * sc_file_new(void)
{
    sc_file_t *file = (sc_file_t *)calloc(1, sizeof(sc_file_t));
    if (file == NULL)
        return NULL;

    file->magic = SC_FILE_MAGIC;
    return file;
}


void sc_file_clear_acl_entries(sc_file_t *file, unsigned int operation)
{
    sc_acl_entry_t *e;

    e = file->acl[operation];
    if (e == (sc_acl_entry_t *) 1 ||
        e == (sc_acl_entry_t *) 2 ||
        e == (sc_acl_entry_t *) 3) {
        file->acl[operation] = NULL;
        return;
    }

    while (e != NULL) {
        sc_acl_entry_t *tmp = e->next;
        free(e);
        e = tmp;
    }
    file->acl[operation] = NULL;
}
*/

int sc_file_add_acl_entry(sc_file_t *file, unsigned int operation,
                          unsigned int method, unsigned long key_ref)
{
    sc_acl_entry_t *p, *_new; 

    switch (method) {         
    case SC_AC_NEVER: 
        sc_file_clear_acl_entries(file, operation);
        file->acl[operation] = (sc_acl_entry_t *) 1;
        return 0;
    case SC_AC_NONE:
        sc_file_clear_acl_entries(file, operation);
        file->acl[operation] = (sc_acl_entry_t *) 2;
        return 0;
    case SC_AC_UNKNOWN:
        sc_file_clear_acl_entries(file, operation);
        file->acl[operation] = (sc_acl_entry_t *) 3;
        return 0;
    default:
        /* NONE and UNKNOWN get zapped when a new AC is added.
 *          * If the ACL is NEVER, additional entries will be
 *                   * dropped silently. */        
        if (file->acl[operation] == (sc_acl_entry_t *) 1)
            return 0;
        if (file->acl[operation] == (sc_acl_entry_t *) 2
         || file->acl[operation] == (sc_acl_entry_t *) 3)
            file->acl[operation] = NULL;
    }  

    /* If the entry is already present (e.g. due to the mapping)
 *      * of the card's AC with OpenSC's), don't add it again. */
    for (p = file->acl[operation]; p != NULL; p = p->next) {
        if ((p->method == method) && (p->key_ref == key_ref))
            return 0;
    }

    _new = (sc_acl_entry_t*)malloc(sizeof(sc_acl_entry_t));
    if (_new == NULL)
        return SC_ERROR_OUT_OF_MEMORY;
    _new->method = method;
    _new->key_ref = key_ref;
    _new->next = NULL;

    p = file->acl[operation];
    if (p == NULL) {
        file->acl[operation] = _new;
        return 0;
    }
    while (p->next != NULL)
        p = p->next;
    p->next = _new;

    return 0;
}

/**                           
 *  * Internal: Implement Access Control List for emulated file.
 *   * The Access Control is derived from the DO access permission.                                                                                                                                                                        
 *    **/   
static void
pgp_attach_acl(card_t *card, sc_file_t *file, struct do_info *info)                                                                                                                                                                 
{
    unsigned int method = SC_AC_NONE;
    unsigned long key_ref = SC_AC_KEY_REF_NONE;                                                                                                                                                                                        

    /* Write access */        
    switch (info->access & WRITE_MASK) {
    case WRITE_NEVER:         
        method = SC_AC_NEVER;
        break;                
    case WRITE_PIN1:          
        method = SC_AC_CHV;   
        key_ref = 0x01;       
        break;                
    case WRITE_PIN2:
        method = SC_AC_CHV;
        key_ref = 0x02;       
        break;                
    case WRITE_PIN3:          
        method = SC_AC_CHV;   
        key_ref = 0x03;       
        break;        
    }  

    if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
        sc_file_add_acl_entry(file, SC_AC_OP_WRITE, method, key_ref);
        sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, method, key_ref);
        sc_file_add_acl_entry(file, SC_AC_OP_DELETE, method, key_ref);
        sc_file_add_acl_entry(file, SC_AC_OP_CREATE, method, key_ref);                                                                                                                                                                 
    }  
    else {
        /* When SC_AC_OP_DELETE is absent, we need to provide
 *          * SC_AC_OP_DELETE_SELF for sc_pkcs15init_delete_by_path() */
        sc_file_add_acl_entry(file, SC_AC_OP_DELETE_SELF, method, key_ref);                                                                                                                                                            
    }  

    method = SC_AC_NONE;
    key_ref = SC_AC_KEY_REF_NONE;  
    /* Read access */
    switch (info->access & READ_MASK) { 
    case READ_NEVER:
        method = SC_AC_NEVER;
        break;
    case READ_PIN1:
        method = SC_AC_CHV;   
        key_ref = 0x01;
        break;
    case READ_PIN2:
        method = SC_AC_CHV;
        key_ref = 0x02;       
        break;
    case READ_PIN3:
        method = SC_AC_CHV;
        key_ref = 0x03;
        break;
    }  
    if (method != SC_AC_NONE || key_ref != SC_AC_KEY_REF_NONE) {
        sc_file_add_acl_entry(file, SC_AC_OP_READ, method, key_ref);
    }
}

/* internal: fill a blob's data */
int pgp_set_blob(struct blob *blob, const u8 *data, size_t len)
{
    if (blob->data)
        free(blob->data);
    blob->data = NULL;
    blob->len    = 0;
    blob->status = 0;

    if (len > 0) {
        void *tmp = calloc(len, 1);

        if (tmp == NULL)
            return SC_ERROR_OUT_OF_MEMORY;

        blob->data = (unsigned char*)tmp;
        blob->len  = len;
        if (data != NULL)
            memcpy(blob->data, data, len);
    }

    if (blob->file)
        blob->file->size = len;

    return SC_SUCCESS;
}

/* internal: append a blob to the list of children of a given parent blob */                                                                                                                                                           
static struct blob *
pgp_new_blob(card_t *card, struct blob *parent, unsigned int file_id,                                                                                                                                                               
        sc_file_t *file)      
{
    struct blob *blob = NULL;

    if (file == NULL)
        return NULL;          

    if ((blob = (struct blob*) calloc(1, sizeof(struct blob))) != NULL) {
        struct pgp_priv_data *priv = DRVDATA (card);
        struct do_info *info; 

        blob->file = file;    

        blob->file->type         = SC_FILE_TYPE_WORKING_EF; /* default */
        blob->file->ef_structure = SC_FILE_EF_TRANSPARENT;      
        blob->file->id           = file_id;                                                                                                                                                                                            

        blob->id     = file_id;        
        blob->parent = parent;

        if (parent != NULL) { 
            struct blob **p;  

            /* set file's path = parent's path + file's id */ 
            blob->file->path = parent->file->path;
            sc_append_file_id(&blob->file->path, file_id);                                                                                                                                                                             

            /* append blob to list of parent's children */
            for (p = &parent->files; *p != NULL; p = &(*p)->next)                                                                                                                                                                      
                ;
            *p = blob;
        }
        else {
            u8 id_str[2];     

            /* no parent: set file's path = file's id */
            /* FIXME sc_format_path expects an hex string of an file
 *              * identifier. ushort2bebytes instead delivers a two bytes binary                                                                                                                                                          
 *                           * string */      
            sc_format_path((char *) ushort2bebytes(id_str, file_id), &blob->file->path);                                                                                                                                               
        }

        /* find matching DO info: set file type depending on it */
        for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {                                                                                                                                                     
            if (info->id == file_id) {         
                blob->info = info;             
                blob->file->type = blob->info->type;
                pgp_attach_acl(card, blob->file, info);                                                                                                                                                                                
                break;
            }
        }
    }  

    return blob;
}


/* internal: iterate through the blob tree, calling a function for each blob */
/*static void
pgp_iterate_blobs(struct blob *blob, int level, void (*func)())
{
    if (blob) {
        if (level > 0) {
            struct blob *child = blob->files;

            while (child != NULL) {            
                struct blob *next = child->next;

                pgp_iterate_blobs(child, level-1, func);
                child = next;
            }
        }
        func(blob);
    }  
}
*/

/* internal: read a blob's contents from card */
static int
pgp_read_blob(card_t *card, struct blob *blob)
{
    if (blob->data != NULL)   
        return SC_SUCCESS;    
    if (blob->info == NULL)   
        return blob->status;  

    if (blob->info->get_fn) {   /* readable, top-level DO */
        u8  buffer[2048];     
        size_t  buf_len = (card->caps & SC_CARD_CAP_APDU_EXT)
                  ? sizeof(buffer) : 256;
        int r = blob->info->get_fn(card, blob->id, buffer, buf_len);

        if (r < 0) {    /* an error occurred */
            blob->status = r;
            return r;
        }

        return pgp_set_blob(blob, buffer, r);
    }
    else {      /* un-readable DO or part of a constructed DO */
        return SC_SUCCESS;
    }
}

/*
 *  * internal: Enumerate contents of a data blob.
 *   * The OpenPGP card has a TLV encoding according ASN.1 BER-encoding rules.                                                                                                                                                             
 *    */    
static int
pgp_enumerate_blob(card_t *card, struct blob *blob)                                                                                                                                                                                 
{
    const u8    *in;
    int     r;

    if (blob->files != NULL)  
        return SC_SUCCESS;

    if ((r = pgp_read_blob(card, blob)) < 0)
        return r;      

    in = blob->data;

    while ((int) blob->len > (in - blob->data)) {
        unsigned int    cla, tag, tmptag;
        size_t      len;
        const u8    *data = in;        
        struct blob *new_blob;

        r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
                    &cla, &tag, &len); 
        if (r < 0) {  
            printf("Unexpected end of contents\n"); 
            return SC_ERROR_OBJECT_NOT_VALID;                                                                                                                                                                                          
        }

        /* undo ASN1's split of tag & class */
        for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {                                                                                                                                                                             
            cla <<= 8;
        }
        tag |= cla;

        /* create fake file system hierarchy by
 *          * using constructed DOs as DF */ 
        if ((new_blob = pgp_new_blob(card, blob, tag, sc_file_new())) == NULL)
            return SC_ERROR_OUT_OF_MEMORY;
        pgp_set_blob(new_blob, data, len);  
        in = data + len;      
    }  

    return SC_SUCCESS;        
}

/* internal: find a blob by ID below a given parent, filling its contents when necessary */                                                                                                                                            
static int
pgp_get_blob(card_t *card, struct blob *blob, unsigned int id,                                                                                                                                                                      
        struct blob **ret)    
{
    struct blob     *child;
    int         r;

    if ((r = pgp_enumerate_blob(card, blob)) < 0)                                                                                                                                                                                      
        return r;

    for (child = blob->files; child; child = child->next) { 
        if (child->id == id) {
            (void) pgp_read_blob(card, child);
            *ret = child;     
            return SC_SUCCESS;
        }
    }  

    return SC_ERROR_FILE_NOT_FOUND;                                                                                                                                                                                                    
}

/* Internal: search recursively for a blob by ID below a given root */                                                                                                                                                                 
static int
pgp_seek_blob(card_t *card, struct blob *root, unsigned int id,                                                                                                                                                                     
        struct blob **ret)    
{
    struct blob *child;       
    int         r;

    if ((r = pgp_get_blob(card, root, id, ret)) == 0)
        /* The sought blob is right under root */                                                                                                                                                                                      
        return r;

    /* Not found, seek deeper */   
    for (child = root->files; child; child = child->next) {
        /* The DO of SIMPLE type or the DO holding certificate
 *          * does not contain children */
        if (child->info->type == SIMPLE || child->id == DO_CERT)                                                                                                                                                                       
            continue;
        r = pgp_seek_blob(card, child, id, ret);
        if (r == 0)
            return r;
    }  

    return SC_ERROR_FILE_NOT_FOUND;                                                                                                                                                                                                    
}

/* internal: find a blob by tag - pgp_seek_blob with optimizations */                                                                                                                                                                  
struct blob * pgp_find_blob(card_t *card, unsigned int tag)                                                                                                                                                                                       
{
    struct pgp_priv_data *priv = DRVDATA(card);
    struct blob *blob = NULL; 
    int r;

printf("CHECKPOINT 2.1.1\n");
    /* Check if current selected blob is which we want to test*/
printf("DEBUG: priv->current->id = %d\n", priv->current->id);
    if (priv->current->id == tag) {
        return priv->current;
    }
printf("CHECKPOINT 2.1.2\n");
    /* Look for the blob representing the DO */
    r = pgp_seek_blob(card, priv->mf, tag, &blob);
    if (r < 0) {
        printf( "Failed to seek the blob representing the tag %04X. Error %d.\n", tag, r);
        return NULL;
    }
    return blob;
}

/* Internal: get info for a specific tag */
static struct do_info *
pgp_get_info_by_tag(card_t *card, unsigned int tag)
{
    struct pgp_priv_data *priv = DRVDATA(card);
    struct do_info *info;     

    for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++)
        if (tag == info->id)  
            return info;

    return NULL;
}

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
    struct do_info  *info;
    int r;
    struct blob     *child = NULL; 

    priv = (pgp_priv_data*)calloc (1, sizeof *priv);
    if (!priv)
        return SC_ERROR_OUT_OF_MEMORY; 
    card->drv_data = priv;

    card->cla = 0x00;

    /* set pointer to correct list of card objects */
    priv->pgp_objects = pgp2_objects; 

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
    sc_format_path("3f00", &file->path);

    /* set up the root of our fake file tree */
    priv->mf = pgp_new_blob(card, NULL, 0x3f00, file);
printf("DEBUG: --------------------------------------------------------\n priv->mf->id = %d\n", priv->mf->id);
    if (!priv->mf) {
        pgp_finish(card);
        return SC_ERROR_OUT_OF_MEMORY; 
    }  

    /* select MF */
    priv->current = priv->mf;

    /* Populate MF - add matching blobs listed in the pgp_objects table. */
    for (info = priv->pgp_objects; (info != NULL) && (info->id > 0); info++) {
        if (((info->access & READ_MASK) == READ_ALWAYS) &&
            (info->get_fn != NULL)) {      
            child = pgp_new_blob(card, priv->mf, info->id, sc_file_new());

            /* catch out of memory condition */
            if (child == NULL) {               
                pgp_finish(card);              
                return SC_ERROR_OUT_OF_MEMORY;                                                                                                                                                                                         
            }
        }
    }  

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


/* ABI: PUT DATA */
int pgp_put_data(card_t *card, unsigned int tag, const u8 *buf, size_t buf_len) 
{
    apdu_t apdu;           
    struct pgp_priv_data *priv = DRVDATA(card);
    struct blob *affected_blob = NULL;
    struct do_info *dinfo = NULL;  
    u8 ins = 0xDA;            
    u8 p1 = tag >> 8;         
    u8 p2 = tag & 0xFF;       
    int r;

    /* Check if the tag is writable */
//    affected_blob = pgp_find_blob(card, tag);

    /* Non-readable DOs have no represented blob, we have to check from pgp_get_info_by_tag */
//    if (affected_blob == NULL)
        dinfo = pgp_get_info_by_tag(card, tag);
//    else
//        dinfo = affected_blob->info;   

    if (dinfo == NULL) {      
        printf( "The DO %04X does not exist.\n", tag);
        LOG_FUNC_RETURN( SC_ERROR_INVALID_ARGUMENTS);
    }
    else if ((dinfo->access & WRITE_MASK) == WRITE_NEVER) {
        printf( "DO %04X is not writable.\n", tag);
        LOG_FUNC_RETURN( SC_ERROR_NOT_ALLOWED);
    }  

    /* Check data size.       
 *      * We won't check other DOs than 7F21 (certificate), because their capacity
 *           * is hard-codded and may change in various version of the card. If we check here,
 *                * the driver may be sticked to a limit version number of card.
 *                     * 7F21 size is soft-coded, so we can check it. */
    if (tag == DO_CERT && buf_len > priv->max_cert_size) {
        printf( "Data size %ld exceeds DO size limit %ld.\n", buf_len, priv->max_cert_size); 
        LOG_FUNC_RETURN( SC_ERROR_WRONG_LENGTH);
    }  

    /* Extended Header list (004D DO) needs a variant of PUT DATA command */
    if (tag == 0x004D) {      
        ins = 0xDB;
        p1 = 0x3F;
        p2 = 0xFF;
    }  

    /* Build APDU */          
    if (buf != NULL && buf_len > 0) { 
        format_apdu(card, &apdu, APDU_CASE_3, ins, p1, p2);

        /* if card/reader does not support extended APDUs, but chaining, then set it */
        if (((card->caps & CARD_CAP_APDU_EXT) == 0) && (priv->ext_caps & EXT_CAP_CHAINING))
            apdu.flags |= APDU_FLAGS_CHAINING;

        apdu.data = (unsigned char*) buf;
        apdu.datalen = buf_len;        
        apdu.lc = buf_len;
    }  
    else {
        format_apdu(card, &apdu, APDU_CASE_1, ins, p1, p2);
    }

    /* Send APDU to card */
    r = transmit_apdu(card, &apdu);
    LOG_TEST_RET( r, "APDU transmit failed");
    /* Check response */
    r = check_sw(card, apdu.sw1, apdu.sw2);

    /* Instruct more in case of error */
    if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
        printf("Please verify PIN first.\n");
    }
    LOG_TEST_RET( r, "PUT DATA returned error");

    if (affected_blob) {
        /* Update the corresponding file */
        printf( "Updating the corresponding blob data\n");
        r = pgp_set_blob(affected_blob, buf, buf_len);
        if (r < 0)
            printf( "Failed to update blob %04X. Error %d.\n", affected_blob->id, r);
        /* pgp_set_blob()'s failures do not impact pgp_put_data()'s result */
    }

    LOG_FUNC_RETURN( buf_len);
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

