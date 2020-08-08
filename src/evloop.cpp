#include "main.hpp"

extern std::atomic_bool interrupted;
extern PPPOEQ pppoe_incoming;
extern PPPOEQ pppoe_outcoming;
extern PPPOEQ ppp_incoming;
extern PPPOEQ ppp_outcoming;
extern std::shared_ptr<PPPOERuntime> runtime;

EVLoop::EVLoop( io_service &i ):
    io( i )
{
    sockaddr_ll sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sll_family = PF_PACKET;
    sockaddr.sll_protocol = bswap16( ETH_P_ALL );
    sockaddr.sll_ifindex = if_nametoindex( runtime->ifName.c_str() );
    sockaddr.sll_hatype = 1;
    int one = 1;
    raw_sock_pppoe.bind( boost::asio::generic::raw_protocol::endpoint( &sockaddr, sizeof( sockaddr ) ) );
    if( setsockopt( raw_sock_pppoe.native_handle(), SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0 ) {
        runtime->logger->logError() << LOGS::MAIN << "Cannot set option PACKET_AUXDATA" << std::endl;
    }

    runtime->logger->logInfo() << LOGS::MAIN << "Listening on interface " << runtime->ifName << std::endl;

    signals.async_wait( [ &, this ]( boost::system::error_code, int signal ) {
        interrupted = true;
        runtime->logger->logInfo() << "Got signal to interrupt, exiting" << std::endl;
        io.stop();
    });

    raw_sock_pppoe.async_wait( boost::asio::socket_base::wait_type::wait_read, std::bind( &EVLoop::receive_pppoe, this, std::placeholders::_1 ) );
    periodic_callback.expires_from_now( boost::asio::chrono::milliseconds( 20 ) );
    periodic_callback.async_wait( std::bind( &EVLoop::periodic, this, std::placeholders::_1 ) );
}

void EVLoop::generic_receive( boost::system::error_code ec, std::size_t len, uint16_t outer_vlan, uint16_t inner_vlan ) {
    if( !ec ) {
        std::vector<uint8_t> pkt { pktbuf.begin(), pktbuf.begin() + len };
        PacketPrint pkt_print { pkt };
        runtime->logger->logInfo() << LOGS::PACKET << pkt_print << std::endl;
        encapsulation_t encap { pkt, outer_vlan, inner_vlan };
        switch( encap.type ) {
        case ETH_PPPOE_DISCOVERY:
            if( auto const &error = pppoe::processPPPOE( pkt, encap ); !error.empty() ) {
                runtime->logger->logError() << LOGS::MAIN << error << std::endl;
            }
            break;
        case ETH_PPPOE_SESSION:
            if( auto const &error = ppp::processPPP( pkt, encap ); !error.empty() ) {
                runtime->logger->logError() << LOGS::MAIN << error << std::endl;
            }
            break;
        default:
            runtime->logger->logInfo() << LOGS::MAIN << "Received packet with unknown ethertype: " << std::hex << std::showbase << encap.type << std::endl;
        }
    }
}

void EVLoop::receive_pppoe( boost::system::error_code ec ) {
    if( ec ) {
        runtime->logger->logError() << LOGS::MAIN << "Error on receiving pppoe: " << ec.message() << std::endl;
        return;
    }
    uint16_t outer_vlan { 0 };
    uint16_t inner_vlan { 0 };

    struct iovec iov = { .iov_base = pktbuf.data(), .iov_len = pktbuf.size() };
    struct cmsghdr cmsg;
    union {
        struct cmsghdr  cmsg;
        char            buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;

    struct msghdr msgh = { 
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = &iov, 
        .msg_iovlen = 1, 
        .msg_control = &cmsg, 
        .msg_controllen = sizeof(cmsg_buf),
        .msg_flags = 0,
    };
    int received = recvmsg( raw_sock_pppoe.native_handle(), &msgh, 0 );
    
    for( auto cmsg = CMSG_FIRSTHDR( &msgh ); cmsg != nullptr; cmsg = CMSG_NXTHDR( &msgh, cmsg ) ) {
        if( cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA ) {
            auto aux_ptr = (struct tpacket_auxdata *)CMSG_DATA( cmsg );
            outer_vlan = aux_ptr->tp_vlan_tci;
        }
    }

    generic_receive( ec, received, outer_vlan, inner_vlan );
    // generic_receive( ec, received, 0, 0 );
    raw_sock_pppoe.async_wait( boost::asio::socket_base::wait_type::wait_read, std::bind( &EVLoop::receive_pppoe, this, std::placeholders::_1 ) );
}

void EVLoop::receive_ppp( boost::system::error_code ec ) {
    if( ec ) {
        runtime->logger->logError() << LOGS::MAIN << "Error on receiving pppoe: " << ec.message() << std::endl;
        return;
    }

    uint16_t outer_vlan { 0 };
    uint16_t inner_vlan { 0 };

    struct iovec iov = { .iov_base = pktbuf.data(), .iov_len = pktbuf.size() };
    struct cmsghdr *cmsg;
        union {
        struct cmsghdr  cmsg;
        char            buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;

    struct msghdr msgh = { 
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = &iov, 
        .msg_iovlen = 1, 
        .msg_control = &cmsg, 
        .msg_controllen = sizeof(cmsg_buf),
        .msg_flags = 0,
    };

    int received = recvmsg( raw_sock_ppp.native_handle(), &msgh, 0 );
    
    for( cmsg = CMSG_FIRSTHDR( &msgh ); cmsg != nullptr; cmsg = CMSG_NXTHDR( &msgh, cmsg ) ) {
        if( cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == PACKET_AUXDATA ) {
            auto aux_ptr = (struct tpacket_auxdata *)CMSG_DATA( cmsg );
            outer_vlan = aux_ptr->tp_vlan_tci;
        }
    }

    // generic_receive( ec, received, outer_vlan, inner_vlan );
    generic_receive( ec, received, 0, 0 );
    raw_sock_ppp.async_wait( boost::asio::socket_base::wait_type::wait_read, std::bind( &EVLoop::receive_ppp, this, std::placeholders::_1 ) );
}

void EVLoop::periodic( boost::system::error_code ec ) {
    if( interrupted ) {
        io.stop();
    }
    // Sending pppoe discovery packets
    while( !pppoe_outcoming.empty() ) {
        auto reply = pppoe_outcoming.pop();
        PacketPrint pkt { reply };
        runtime->logger->logInfo() << LOGS::PACKET << pkt << std::endl;
        // ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
        // rep_eth->src_mac = runtime->hwaddr;
        raw_sock_pppoe.send( boost::asio::buffer( reply ) );
    }
    // Sending pppoe session control packets
    while( !ppp_outcoming.empty() ) {
        auto reply = ppp_outcoming.pop();
        PacketPrint pkt { reply };
        runtime->logger->logInfo() << LOGS::PACKET << pkt << std::endl;
        raw_sock_pppoe.send( boost::asio::buffer( reply ) );
    }
    periodic_callback.expires_from_now( boost::asio::chrono::milliseconds( 20 ) );
    periodic_callback.async_wait( std::bind( &EVLoop::periodic, this, std::placeholders::_1 ) );
}