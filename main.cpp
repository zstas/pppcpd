#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

int main( int argc, char *argv[] ) {
    struct sockaddr_ll sa;
    int sock = 0;

    if( sock = socket( AF_INET, SOCK_RAW, PF_PACKET ); sock < 0 ) {
        if( errno == EPERM ) {
            printf( "Not enought priviligies to open raw socket\n" );
            exit( -1 );
        }
    }
    if( int optval=1; setsockopt( sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof( optval ) ) < 0 ) {
        printf( "Cannot exec setsockopt\n" );
    }

    // 
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons( ETH_PPPOE_DISCOVERY );


    return 0;
}