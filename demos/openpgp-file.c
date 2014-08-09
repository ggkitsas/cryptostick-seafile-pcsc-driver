#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openpgp-msg.h"



int main()
{
    pgp_message msg;
    pgp_read_msg_file("/home/cyc0/Desktop/sub.pubring.gpg", &msg);
 
    printf("Type: %d\n", msg.packet_type);
    pgp_print_pubkey_packet( (pgp_pubkey_packet*)(msg.pgp_packet) );
    
    return 0;
}
