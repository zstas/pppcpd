#include <iostream>
#include <vector>
#include <cstring>

// Network api
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

void printHex( std::vector<uint8_t> pkt ) {
    for( auto &byte: pkt ) {
        printf( "%02x ", byte );
    }
    printf( "\n" );
}

int main( int argc, char *argv[] ) {
    auto ifname = "pppoe-cp";
    struct sockaddr_ll sa;
    int sock = 0;

    if( sock = socket( PF_PACKET, SOCK_RAW, htons( ETH_PPPOE_DISCOVERY ) ); sock < 0 ) {
        if( errno == EPERM ) {
            printf( "Not enought priviligies to open raw socket\n" );
            exit( -1 );
        }
    }
    if( int optval=1; setsockopt( sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof( optval ) ) < 0 ) {
        printf( "Cannot exec setsockopt\n" );
    }

    // Handling pppoe discovery packets
    memset( &sa, 0, sizeof( sa ) );
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons( ETH_PPPOE_DISCOVERY );

    struct ifreq ifr;
    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ );
    ifr.ifr_ifrn.ifrn_name[ IFNAMSIZ - 1 ] = 0;

    char hwaddr[ ETH_ALEN ];
    if( ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
	    printf( "ioctl(SIOCGIFHWADDR)\n" );
        exit( -1 );
	}
	memcpy( hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if( ioctl( sock, SIOCGIFINDEX, &ifr ) < 0) {
	    printf( "Cannot get ifindex for interface" );
        exit( -1 );
    }
    printf( "Ifindex: %d\n", ifr.ifr_ifindex );
    sa.sll_ifindex = ifr.ifr_ifindex;

    if( bind( sock, (struct sockaddr *) &sa, sizeof( sa ) ) < 0 ) {
        printf( "Cannot bind on interface: %s\n", strerror( errno ) );
        exit( -1 );
    }

    std::vector<uint8_t> pkt;
    pkt.resize( 1508 );

    while( true ) {
        if( auto ret = recv( sock, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
            printf( "Get %ld bytes\n", ret );
            pkt.resize( ret );
            printHex( pkt );
        }
    }

    return 0;
}