#include "openpgp-msg.h"


int read_pgp_packet(FILE* fp, pgp_packet_header* hdr)
{
    int i;

    hdr = (pgp_packet_header*) calloc(1, sizeof(pgp_packet_header));
    
    // Header Tag
    unsigned char ptag;
    ptag = fgetc(fp);
    // validation
    if ( !VALIDATE_TAG(ptag) ) {
        printf("Not a packet header\n");
        return -1;
    }
    hdr->ptag = ptag;
    unsigned int old_packet = IS_OLD_FORMAT(hdr->ptag);

    unsigned int length_len;
    if (old_packet) {
        CALC_LENGTH_LEN (tag, length_len);
        hdr->length = (unsigned char*) calloc(1, sizeof(unsigned char*));
        for(i=0; i<length_len; i++) {
            hdr->length[i] = fgetc(fp);
        }
    } else { // New packet format
    }

    
    pgp_pubkey_packet pubkey_pkt;
    if ( IS_PUB_KEY_PACKET(hdr->ptag) || IS_SECRET_KEY_PACKET(hdr->ptag) ) {
        pubkey_pkt.version = fgetc(fp);
    }

    if ( IS_SECRET_KEY_PACKET(hdr->ptag) ) {
    }

    return 0;
}

int read_pgg_msg_file(const char* filepath)
{
    FILE* fp = fopen(filepath,"r");
    if(!fp) {
        printf("Error while opening file %s\n", filepath);
        return -1;
    }

    

    fclose(fp);
    return 0;
}
