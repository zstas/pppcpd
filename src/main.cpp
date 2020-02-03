#include "main.hpp"

// Some global vars
std::shared_ptr<PPPOERuntime> runtime;
std::atomic_bool interrupted { false };

// Queues for packets
PPPOEQ pppoe_incoming;
PPPOEQ pppoe_outcoming;
PPPOEQ ppp_incoming;
PPPOEQ ppp_outcoming;

void sighandler( int signal ) {
    interrupted = true;
}

int main( int argc, char *argv[] ) {
    std::signal( SIGINT, sighandler );
    std::signal( SIGTERM, sighandler );
    runtime = std::make_shared<PPPOERuntime>( "pppoe-cp" );

    if( auto const &err = runtime->setupPPPOEDiscovery(); !err.empty() ) {
        log( "Cannot start pppoe control daemon: " + err );
        exit( -1 );
    }

    if( auto const &err = runtime->setupPPPOESession(); !err.empty() ) {
        log( "Cannot start pppoe control daemon: " + err );
        exit( -1 );
    }

    // At this point all the config lies here
    runtime->pppoe_conf = std::make_shared<PPPOEPolicy>();
    runtime->pppoe_conf->ac_name = "vBNG AC PPPoE";
    runtime->pppoe_conf->insertCookie = true;
    runtime->pppoe_conf->ignoreServiceName = true;

    // LCP options
    runtime->lcp_conf = std::make_shared<LCPPolicy>();

    runtime->aaa = std::make_shared<AAA>( 0x6440000A, 0x644000FE, 0x08080808, 0x01010101 );
    runtime->vpp = std::make_shared<VPPAPI>();

    std::thread pppoe_dispatcher ([]() -> void {
        while( !interrupted ) {
            auto pkt = pppoe_incoming.pop();
            if( auto const &[ reply, error ] = pppoe::processPPPOE( pkt ); !error.empty() ) {
                log( error );
            } else {
                pppoe_outcoming.push( reply );
            }
        }
    });

    std::thread ppp_dispatcher ([]() -> void {
        while( !interrupted ) {
            auto pkt = ppp_incoming.pop();
            if( auto const error = ppp::processPPP( pkt ); !error.empty() ) {
                log( error );
            }
        }
    });

    EVLoop loop;

    pppoe_dispatcher.join();
    ppp_dispatcher.join();

    return 0;
}

std::string PPPOERuntime::setupPPPOEDiscovery() {
    struct sockaddr_ll sa;

    if( PPPOEDiscFD = socket( PF_PACKET, SOCK_RAW, htons( ETH_PPPOE_DISCOVERY ) ); PPPOEDiscFD < 0 ) {
        return "Cannot open socket for PPPOE Discovery packets: "s + strerror( errno );
    }
    if( int optval = 1; setsockopt( PPPOEDiscFD, SOL_SOCKET, SO_BROADCAST, &optval, sizeof( optval ) ) < 0 ) {
        return "Cannot exec setsockopt: "s + strerror( errno );
    }

    // Handling pppoe discovery packets
    memset( &sa, 0, sizeof( sa ) );
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons( ETH_PPPOE_DISCOVERY );

    struct ifreq ifr;
    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_ifrn.ifrn_name, ifName.c_str(), IFNAMSIZ );
    ifr.ifr_ifrn.ifrn_name[ IFNAMSIZ - 1 ] = 0;

    if( ioctl( PPPOEDiscFD, SIOCGIFHWADDR, &ifr ) < 0) {
	    return "ioctl(SIOCGIFHWADDR)";
	}
	memcpy( hwaddr.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    if( ioctl( PPPOEDiscFD, SIOCGIFINDEX, &ifr ) < 0) {
	    return "Cannot get ifindex for interface";
    }

    log( "Ifindex: "s + std::to_string( ifr.ifr_ifindex ) );
    sa.sll_ifindex = ifr.ifr_ifindex;

    if( bind( PPPOEDiscFD, reinterpret_cast<struct sockaddr*>( &sa ), sizeof( sa ) ) < 0 ) {
        return "Cannot bind on interface: "s + strerror( errno );
    }

    return "";
}

std::string PPPOERuntime::setupPPPOESession() {
    struct sockaddr_ll sa;

    if( PPPOESessFD = socket( PF_PACKET, SOCK_RAW, htons( ETH_PPPOE_SESSION ) ); PPPOESessFD < 0 ) {
        return "Cannot open socket for PPPOE Discovery packets: "s + strerror( errno );
    }

    // Handling pppoe session packets
    memset( &sa, 0, sizeof( sa ) );
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons( ETH_PPPOE_SESSION );

        struct ifreq ifr;
    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_ifrn.ifrn_name, ifName.c_str(), IFNAMSIZ );
    ifr.ifr_ifrn.ifrn_name[ IFNAMSIZ - 1 ] = 0;

    if( ioctl( PPPOEDiscFD, SIOCGIFINDEX, &ifr ) < 0) {
	    return "Cannot get ifindex for interface";
    }

    log( "Ifindex: "s + std::to_string( ifr.ifr_ifindex ) );
    sa.sll_ifindex = ifr.ifr_ifindex;


    if( bind( PPPOESessFD, reinterpret_cast<struct sockaddr*>( &sa ), sizeof( sa ) ) < 0 ) {
        return "Cannot bind on interface: "s + strerror( errno );
    }

    return "";
}