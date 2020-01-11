#include "main.hpp"

// Some global vars
std::shared_ptr<PPPOERuntime> runtime;

// Queues for packets
PPPOEQ pppoe_incoming;
PPPOEQ pppoe_outcoming;
PPPOEQ ppp_incoming;
PPPOEQ ppp_outcoming;

int main( int argc, char *argv[] ) {
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
    runtime->policy = std::make_shared<PPPOEPolicy>();
    runtime->policy->ac_name = "vBNG AC PPPoE";
    runtime->policy->insertCookie = true;
    runtime->policy->ignoreServiceName = true;

    std::vector<uint8_t> pkt;
    pkt.resize( 1508 );

    std::thread pppoe_dispatcher ([]() -> void {
        while( true ) {
            if( pppoe_incoming.empty() ) {
                continue;
            }
            auto pkt = pppoe_incoming.pop();
            if( auto const &[ reply, error ] = pppoe::processPPPOE( pkt ); !error.empty() ) {
                log( error );
            } else {
                pppoe_outcoming.push( reply );
            }
        }
    });

    std::thread ppp_dispatcher ([]() -> void {
        while( true ) {
            if( ppp_incoming.empty() ) {
                continue;
            }
            auto pkt = ppp_incoming.pop();
            if( auto const error = ppp::processPPP( pkt ); !error.empty() ) {
                log( error );
            }
        }
    });

    struct pollfd fds[ 2 ];
    fds[ 0 ].fd = runtime->PPPOEDiscFD;
    fds[ 0 ].events = POLLIN;
    fds[ 1 ].fd = runtime->PPPOESessFD;
    fds[ 1 ].events = POLLIN;

    while( true ) {
        if( int ret = poll( reinterpret_cast<pollfd*>( &fds ), 2, 10000 ); ret == -1 ) {
            log( "Poll returned error: "s + strerror( errno ) );
        } else if( ret > 0 ) {
            if( fds[ 0 ].revents & POLLIN ) {
                // Receiving pppoe discovery packets
                if( auto ret = recv( runtime->PPPOEDiscFD, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
                    pkt.resize( ret );
                    pppoe_incoming.push( pkt );
                }
            }
            if( fds[ 1 ].revents & POLLIN ) {
                // Receiving pppoe session control packets (lcp, ipcp, ipcp6, etc)
                if( auto ret = recv( runtime->PPPOESessFD, pkt.data(), pkt.capacity(), 0 ); ret > 0 ) {
                    pkt.resize( ret );
                    ppp_incoming.push( pkt );
                }
            }
        }
        // Sending pppoe discovery packets
        while( !pppoe_outcoming.empty() ) {
            auto reply = pppoe_outcoming.pop();
            ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
            rep_eth->src_mac = runtime->hwaddr;
            if( auto ret = send( runtime->PPPOEDiscFD, reply.data(), reply.size(), 0 ); ret < 0 ) {
                log( "Cannot send pkt cause: "s + strerror( errno ) );
            }
        }
    }

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