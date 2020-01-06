#include "main.hpp"

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

uint16_t lastSession = 0;
std::set<uint16_t> sessionSet;
std::map<uint8_t[8], uint8_t> pppoeSessions;
std::shared_ptr<PPPOEPolicy> policy;

// Queues for packets
PPPOEQ pppoe_incoming;
PPPOEQ pppoe_outcoming;

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
    if( int optval = 1; setsockopt( sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof( optval ) ) < 0 ) {
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

    std::array<uint8_t,ETH_ALEN> hwaddr;
    if( ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
	    log( "ioctl(SIOCGIFHWADDR)" );
        exit( -1 );
	}
	memcpy( hwaddr.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if( ioctl( sock, SIOCGIFINDEX, &ifr ) < 0) {
	    log( "Cannot get ifindex for interface" );
        exit( -1 );
    }
    log( "Ifindex: "s + std::to_string( ifr.ifr_ifindex ) );
    sa.sll_ifindex = ifr.ifr_ifindex;

    if( bind( sock, reinterpret_cast<struct sockaddr*>( &sa ), sizeof( sa ) ) < 0 ) {
        log( "Cannot bind on interface: "s + strerror( errno ) );
        exit( -1 );
    }

    // At this point all the config lies here
    policy = std::make_shared<PPPOEPolicy>();
    policy->ac_name = "vBNG AC PPPoE";
    policy->insertCookie = true;
    policy->ignoreServiceName = true;

    std::vector<uint8_t> pkt;
    pkt.resize( 1508 );

    std::thread pppoe_dispatcher ([]() -> void {
        while( true ) {
            if( pppoe_incoming.empty() ) {
                continue;
            }
            auto pkt = pppoe_incoming.pop();
            if( auto const &[ reply, error ] = dispatchPPPOE( pkt ); !error.empty() ) {
                log( error );
            } else {
                pppoe_outcoming.push( reply );
            }
        }
    });

    while( true ) {
        if( auto ret = recv( sock, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
            log( "Got pkt with len " + std::to_string( ret ) );
            pkt.resize( ret );
            pppoe_incoming.push( pkt );
        }
        if( !pppoe_outcoming.empty() ) {
            auto reply = pppoe_outcoming.pop();
            ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
            rep_eth->src_mac = hwaddr;
            if( auto ret = send( sock, reply.data(), reply.size(), 0 ); ret < 0 ) {
                log( "Cannot send pkt cause: "s + strerror( errno ) );
            }
        }
    }

    return 0;
}

std::tuple<std::vector<uint8_t>,std::string> dispatchPPPOE( std::vector<uint8_t> pkt ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( ETHERNET_HDR ) + sizeof( PPPOEDISC_HDR ) + 128 );
    uint16_t session_id = 0;

    printHex( pkt );
    ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    log( "Ethernet packet:\n" + ether::to_string( eth ) );
    if( eth->ethertype != htons( ETH_PPPOE_DISCOVERY ) ) {
        return { std::move( reply ), "Not pppoe packet" };
    }
    PPPOEDISC_HDR *pppoe = reinterpret_cast<PPPOEDISC_HDR*>( pkt.data() + sizeof( ETHERNET_HDR ) );

    reply.resize( sizeof( ETHERNET_HDR ) + sizeof( PPPOEDISC_HDR ) );
    log( "Incoming PPPoE packet:\n" + pppoe::to_string( pppoe ) );
    
    for( uint16_t i = 1; i < UINT16_MAX; i++ ) {
        if( auto ret = sessionSet.find( i ); ret == sessionSet.end() ) {
            sessionSet.emplace( i );
            session_id = i;
            break;
        } 
    }

    uint8_t key[ 8 ];
    std::memcpy( key, eth->src_mac.data(), 6 );
    *reinterpret_cast<uint16_t*>( &key[ 6 ] ) = htons( session_id );
    
    if( auto const &sIt = pppoeSessions.find( key ); sIt != pppoeSessions.end() ) {
        return { std::move( reply ), "Session is already up" };
    }

    ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
    rep_eth->ethertype = htons( ETH_PPPOE_DISCOVERY );
    rep_eth->dst_mac = eth->src_mac;

    PPPOEDISC_HDR *rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->type = 1;
    rep_pppoe->version = 1;
    rep_pppoe->session_id = 0;
    rep_pppoe->length = 0;

    // Starting to prepare the answer
    switch( pppoe->code ) {
    case PPPOE_CODE::PADI:
        log( "Processing PADI packet" );
        rep_pppoe->code = PPPOE_CODE::PADO;
        break;
    case PPPOE_CODE::PADR:
        log( "Processing PADR packet" );
        rep_pppoe->code = PPPOE_CODE::PADS;
        rep_pppoe->session_id = session_id;
        break;
    case PPPOE_CODE::PADT:
        log( "Processing PADT packet" );
        // TODO security check for session
        return { std::move( reply ), "Received PADT, doing nothing" };
    default:
        log( "Incorrect code for packet" );
        return { std::move( reply ), "Incorrect code for packet" };
    }

    // Parsing tags
    std::optional<std::string> chosenService;
    std::optional<std::string> hostUniq;
    if( auto const &[ tags, error ] = pppoe::parseTags( pkt ); !error.empty() ) {
        return { std::move( reply ), "Cannot parse tags cause: " + error };
    } else {
        for( auto &[ tag, val ]: tags ) {
            log( "Processing tag: " + std::to_string( static_cast<uint16_t>( tag ) ) );
            switch( tag ) {
            case PPPOE_TAG::AC_NAME:
                break;
            case PPPOE_TAG::AC_COOKIE:
                break;
            case PPPOE_TAG::HOST_UNIQ:
                if( !val.empty() ) {
                    hostUniq = val;
                }
                break;
            case PPPOE_TAG::VENDOR_SPECIFIC:
                break;
            case PPPOE_TAG::RELAY_SESSION_ID:
                break;
            case PPPOE_TAG::AC_SYSTEM_ERROR:
                break;
            case PPPOE_TAG::GENERIC_ERROR:
                break;
            case PPPOE_TAG::SERVICE_NAME:
                // RFC 2516:
                // If the Access Concentrator can not serve the PADI it MUST NOT respond with a PADO.
                if( !val.empty() && val != policy->service_name ) {
                    if( policy->ignoreServiceName ) {
                        log( "Service name is differ, but we can ignore it" );
                        chosenService = val;
                    } else {
                        return { std::move( reply ), "Cannot serve \"" + val + "\" service, because in policy only \"" + policy->service_name + "\"" };
                    }
                }
                break;
            case PPPOE_TAG::SERVICE_NAME_ERROR:
                break;
            case PPPOE_TAG::END_OF_LIST:
                break;
            }
        }
    }

    // Inserting tags
    auto taglen = 0;
    taglen += pppoe::insertTag( reply, PPPOE_TAG::AC_NAME, policy->ac_name );

    if( chosenService.has_value() ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::SERVICE_NAME, chosenService.value() );
    } else {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::SERVICE_NAME, policy->service_name );
    }

    if( hostUniq.has_value() ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::HOST_UNIQ, hostUniq.value() );
    }

    if( policy->insertCookie ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::AC_COOKIE, random_string( 16 ) );
    }

    // In case of vector is increased
    rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->length = htons( taglen );
    log( "Outcoming PPPoE packet:\n" + pppoe::to_string( rep_pppoe ) );

    return { std::move( reply ), "" };
}
