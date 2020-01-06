#include "main.hpp"

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

uint16_t lastSession = 0;
std::set<uint16_t> sessionSet;
std::map<uint8_t[8], uint8_t> pppoeSessions;
std::shared_ptr<PPPOEPolicy> policy;

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

    if( bind( sock, (struct sockaddr *) &sa, sizeof( sa ) ) < 0 ) {
        log( "Cannot bind on interface: "s + strerror( errno ) );
        exit( -1 );
    }

    policy = std::make_shared<PPPOEPolicy>();
    policy->ac_name = "vBNG AC PPPoE";
    policy->insertCookie = false;

    std::vector<uint8_t> pkt;
    pkt.resize( 1508 );

    while( true ) {
        if( auto ret = recv( sock, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
            pkt.resize( ret );
            if( auto [ reply, err ] = dispatchPPPOE( pkt ); !err.empty() ) {
                log( "err processing pkt: " + err );
            } else {
                log( "pkt is good, sending answer with len " + std::to_string( reply.size() ) );
                ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
                rep_eth->src_mac = hwaddr;
                if( auto ret = send( sock, reply.data(), reply.size(), 0 ); ret < 0 ) {
                    log( "Cannot send pkt cause: "s + strerror( errno ) );
                }
            }
        }
    }

    return 0;
}

std::tuple<std::vector<uint8_t>,std::string> dispatchPPPOE( std::vector<uint8_t> pkt ) {
    std::vector<uint8_t> reply;
    uint16_t session_id = 0;

    ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    log( "Ethernet packet:\n" + ether::to_string( eth ) );
    if( eth->ethertype != htons( ETH_PPPOE_DISCOVERY ) ) {
        return { reply, "Not pppoe packet" };
    }
    PPPOEDISC_HDR *pppoe = reinterpret_cast<PPPOEDISC_HDR*>( pkt.data() + sizeof( ETHERNET_HDR ) );

    reply.resize( sizeof( ETHERNET_HDR ) + sizeof( PPPOEDISC_HDR ) );
    log( "PPPoE packet:\n" + pppoe::to_string( pppoe ) );
    
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
        return { reply, "Session is already up" };
    }

    ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
    rep_eth->ethertype = htons( ETH_PPPOE_DISCOVERY );
    rep_eth->dst_mac = eth->src_mac;

    PPPOEDISC_HDR *rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->type = 1;
    rep_pppoe->version = 1;
    rep_pppoe->session_id = 0;
    rep_pppoe->length = 0;

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
    default:
        log( "Incorrect code for packet" );
        return { reply, "Incorrect code for packet" };
    }

    PPPOEDISC_TLV *tlv = nullptr;
    std::map<PPPOE_TAG,std::string> tags;
    auto offset = pkt.data() + sizeof( ETHERNET_HDR) + sizeof( PPPOEDISC_HDR );
    while( true ) {
        tlv = reinterpret_cast<PPPOEDISC_TLV*>( offset );
        auto tag = PPPOE_TAG { ntohs( tlv->type ) };
        log( "Parsed tag: " + std::to_string( ntohs( tlv->type ) ) );
        auto len = ntohs( tlv->length );
        std::string val;
        if( len > 0 ) {
            val = std::string { (char*)tlv->value, len };
        }

        if( auto const &[ it, ret ] = tags.emplace( tag, val ); !ret ) {
            return { reply, "Cannot insert tag in tag map" };
        }

        offset += 4 + len;
        if( offset >= pkt.end().base() ) {
            break;
        }
    }

    for( auto &[ tag, val ]: tags ) {
        log( "Processing tag: " + std::to_string( static_cast<uint16_t>( tag ) ) );
        PPPOEDISC_TLV *tlv = nullptr;

        switch( tag ) {
        case PPPOE_TAG::AC_NAME:
            break;
        case PPPOE_TAG::AC_COOKIE:
            break;
        case PPPOE_TAG::HOST_UNIQ:
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
            break;
        case PPPOE_TAG::SERVICE_NAME_ERROR:
            break;
        case PPPOE_TAG::END_OF_LIST:
            break;
        }
    }

    // Inserting tags
    auto taglen = 0;
    taglen += insertTag( reply, PPPOE_TAG::AC_NAME, policy->ac_name );
    taglen += insertTag( reply, PPPOE_TAG::SERVICE_NAME, policy->service_name );

    rep_pppoe->length == htons( sizeof( PPPOEDISC_HDR) + taglen );

    return { reply, "" };
}

uint8_t insertTag( std::vector<uint8_t> &pkt, PPPOE_TAG tag, std::string val ) {
    std::vector<uint8_t> tagvec;
    tagvec.resize( 4 );
    auto tlv = reinterpret_cast<PPPOEDISC_TLV*>( tagvec.data() );
    tlv->type = htons( static_cast<uint16_t>( tag ) );
    tlv->length = htons( val.size() );
    tagvec.insert( tagvec.end(), val.begin(), val.end() );
    pkt.insert( pkt.end(), tagvec.begin(), tagvec.end() );     

    return tagvec.size();
}