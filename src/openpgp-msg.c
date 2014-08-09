#include "openpgp-msg.h"


void pgp_print_pubkey_packet(pgp_pubkey_packet* pgp_packet)
{
    int i;

    printf("Version: %.2x\n", pgp_packet->version);
    printf("Time: ");
    for(i=0; i<4; i++)
        printf("%.2x ", pgp_packet->creation_time[i]);
    printf("\n");

    printf("Algorithm: %d\n", pgp_packet->algo);

    printf("Modulus: ");
    for(i=0; i<256; i++)
        printf("%.2x ", pgp_packet->modulus[i]);
    printf("\n");
 
    printf("Exponent: ");
    for(i=0; i<4; i++)
        printf("%.2x ", pgp_packet->exponent[i]);
    printf("\n");
}



int pgp_read_pubkey_packet(FILE* fp, pgp_pubkey_packet** pubkey_packet)
{
    int i;
    // TODO: calc (or get from parameter) modulus length
    unsigned int modulus_length = 256;
    pgp_pubkey_packet* pubkey_pkt = (pgp_pubkey_packet*) calloc(1, sizeof(pgp_pubkey_packet));

    // TODO: Read version 3
    unsigned char version = fgetc(fp);
    pubkey_pkt->version = version;
    for(i=0; i<4; i++)
        pubkey_pkt->creation_time[i] = fgetc(fp);
    pubkey_pkt->algo = fgetc(fp);

    pubkey_pkt->modulus = (unsigned char*) malloc(sizeof(unsigned char) * modulus_length);
    for(i=0; i<modulus_length; i++)
        pubkey_pkt->modulus[i] = fgetc(fp);
    for(i=0; i<3; i++)
        pubkey_pkt->exponent[i] = fgetc(fp);

    *pubkey_packet = pubkey_pkt;
    return 0;
}



int pgp_read_packet(FILE* fp, void** pgp_packet, pgp_packet_header** hdr)
{
    int i;
    pgp_packet_header* tmp_hdr = (pgp_packet_header*) calloc(1, sizeof(pgp_packet_header));
    
    // Header Tag
    unsigned char ptag;
    ptag = fgetc(fp);
    if ( !VALIDATE_TAG(ptag) ) {
        printf("Not a packet header\n");
        return -1;
    }
    tmp_hdr->ptag = ptag;
    unsigned int old_packet = IS_OLD_FORMAT(tmp_hdr->ptag);

    // TODO: convert packet length to int
    unsigned int length_len;
    if (old_packet) {
        length_len = CALC_LENGTH_LEN (tmp_hdr->ptag);
        tmp_hdr->length = (unsigned char*) calloc(1, sizeof(unsigned char*));
        for(i=0; i<length_len; i++) {
            tmp_hdr->length[i] = fgetc(fp);
        }
    } else { // New packet format
    }

    if ( IS_PUB_KEY_PACKET(tmp_hdr->ptag)) {
        pgp_pubkey_packet* pub_packet;
        pgp_read_pubkey_packet(fp, &pub_packet);
        *pgp_packet = (void*)pub_packet;
    }

    // TODO: read secret key packet fields
    if ( IS_SECRET_KEY_PACKET(tmp_hdr->ptag) ) {
    }

    *hdr = tmp_hdr;
    return 0;
}

int pgp_read_msg_file(const char* filepath, pgp_message* msg)
{
    FILE* fp = fopen(filepath,"r");
    if(!fp) {
        perror("Error");
        return -1;
    }

    // TODO:
    // read ALL packets belonging to a message
    void* pgp_packet;
    pgp_packet_header* hdr;
    pgp_read_packet(fp, &pgp_packet, &hdr);
    msg->packet_type = GET_TAG(hdr->ptag);
    msg->pgp_packet = pgp_packet;
    msg->next = NULL;

    
    fclose(fp);
    return 0;
}
