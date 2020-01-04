#include "main.hpp"

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

uint16_t lastSession = 0;
std::set<uint16_t> sessionSet;
std::map<uint8_t[8], uint8_t> pppoeSessions;

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
            log( "Not enought priviligies to open raw socket" );
            exit( -1 );
        }
    }
    if( int optval=1; setsockopt( sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof( optval ) ) < 0 ) {
        log( "Cannot exec setsockopt" );
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
	    log( "ioctl(SIOCGIFHWADDR)" );
        exit( -1 );
	}
	memcpy( hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if( ioctl( sock, SIOCGIFINDEX, &ifr ) < 0) {
	    log( "Cannot get ifindex for interface" );
        exit( -1 );
    }
    log( "Ifindex: "s + std::to_string( ifr.ifr_ifindex ) );
    sa.sll_ifindex = ifr.ifr_ifindex;

    if( bind( sock, (struct sockaddr *) &sa, sizeof( sa ) ) < 0 ) {
        log( "Cannot bind on interface: "s + strerror( errno ) );
        exit( -1 );
    }

    std::vector<uint8_t> pkt;
    pkt.resize( 1508 );

    while( true ) {
        if( auto ret = recv( sock, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
            pkt.resize( ret );
            auto eth = EthernetHeader( { pkt.begin(), pkt.begin() + 14 } );
            log( "Ethernet packet:\n" + eth.toString() );
            if( eth.ethertype == htons( ETH_PPPOE_DISCOVERY ) ) {
                auto pppoe = PPPoE_Discovery( { pkt.begin() + 14, pkt.end() } );
                if( auto const &[pkt, err] = dispatchPPPOE( eth.src_mac, pppoe ); !err.empty() ) {
                    log( "err processing pkt: " + err );
                } else {
                    log( "pkt is good, sending answer" );
                    //send()
                }
            } else {
                log( "unknown ethertype" );
            }
        }
    }

    return 0;
}

std::tuple<PPPoE_Discovery,std::string> dispatchPPPOE( uint8_t mac[6], PPPoE_Discovery inPkt ) {
    log( "PPPoE packet:\n" + inPkt.toString() );
    
    uint16_t session_id = 0;
    for( uint16_t i = 1; i < UINT16_MAX; i++ ) {
        if( auto ret = sessionSet.find( i ); ret == sessionSet.end() ) {
            sessionSet.emplace( i );
            session_id = i;
            break;
        } 
    }

    uint8_t key[ 8 ];
    std::memcpy( key, mac, 8 );
    *reinterpret_cast<uint16_t*>( &key[ 6 ] ) = htons( session_id );
    
    if( auto const &sIt = pppoeSessions.find( key ); sIt != pppoeSessions.end() ) {
        return { PPPoE_Discovery(), "Session is already up" };
    }

    switch( inPkt.code ) {
    case PPPOE_CODE::PADI:
        log( "Processing PADI packet" );
        //
        break;
    case PPPOE_CODE::PADR:
        log( "Processing PADR packet" );
        //
        break;
    default:
        log( "Incorrect code for packet" );
        return { PPPoE_Discovery(), "Incorrect code for packet" };
    }
    return { PPPoE_Discovery(), "" };
}