#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <memory>
#include <random>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <csignal>
#include <condition_variable>

// Network api
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <poll.h>
#include <boost/asio.hpp>
#include <boost/asio/basic_raw_socket.hpp>

// Local headers
#include "encap.hpp"
#include "pppoe.hpp"
#include "ethernet.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "tools.hpp"
#include "ppp_lcp.hpp"
#include "ppp_ipcp.hpp"
#include "ppp.hpp"
#include "ppp_fsm.hpp"
#include "ppp_auth.hpp"
#include "session.hpp"
#include "string_helpers.hpp"
#include "packet.hpp"
#include "aaa.hpp"
#include "vpp.hpp"
#include "runtime.hpp"

using namespace std::string_literals;

extern std::atomic_bool interrupted;

struct PPPOEQ {
    std::mutex mutex;
    std::condition_variable cond;
    std::queue<std::vector<uint8_t>> queue;

    void push( std::vector<uint8_t> pkt ) {
        std::unique_lock lg( mutex );
        queue.push( std::move( pkt ) );
        cond.notify_one();
    }

    std::vector<uint8_t> pop() {
        std::unique_lock lg{ mutex };
        while( queue.empty() ) {
            cond.wait_for( lg, std::chrono::seconds( 1 ) );
            if( interrupted ) {
                exit( 0 );
            }
        }
        auto ret = queue.front();
        queue.pop();
        return ret;
    }

    bool empty() {
        std::lock_guard lg( mutex );
        return queue.empty();
    }
};

extern PPPOEQ pppoe_incoming;
extern PPPOEQ pppoe_outcoming;
extern PPPOEQ ppp_incoming;
extern PPPOEQ ppp_outcoming;
extern std::shared_ptr<PPPOERuntime> runtime;

class EVLoop {
private:
    boost::asio::io_context io;
    boost::asio::signal_set signals{ io, SIGTERM, SIGINT };
    std::array<uint8_t,1500> pktbuf;

    boost::asio::generic::raw_protocol pppoed { PF_PACKET, SOCK_RAW };
    boost::asio::generic::raw_protocol pppoes { PF_PACKET, SOCK_RAW };
    boost::asio::generic::raw_protocol vlan { PF_PACKET, SOCK_RAW };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_pppoe { io, pppoed };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_ppp { io, pppoes };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_vlan { io, vlan };
    boost::asio::steady_timer periodic_callback{ io, boost::asio::chrono::seconds( 1 ) };
public:
    EVLoop() {
        sockaddr_ll sockaddr;
        memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.sll_family = PF_PACKET;
        sockaddr.sll_protocol = htons( ETH_PPPOE_DISCOVERY );
        sockaddr.sll_ifindex = if_nametoindex( runtime->ifName.c_str() );
        sockaddr.sll_hatype = 1;
        raw_sock_pppoe.bind( boost::asio::generic::raw_protocol::endpoint( &sockaddr, sizeof( sockaddr ) ) );

        sockaddr.sll_protocol = htons( ETH_PPPOE_SESSION );
        raw_sock_ppp.bind( boost::asio::generic::raw_protocol::endpoint( &sockaddr, sizeof( sockaddr ) ) );

        sockaddr.sll_protocol = htons( ETH_VLAN );
        raw_sock_vlan.bind( boost::asio::generic::raw_protocol::endpoint( &sockaddr, sizeof( sockaddr ) ) );

        signals.async_wait( [ &, this ]( boost::system::error_code, int signal ) {
            interrupted = true;
            io.stop();
        });

        raw_sock_pppoe.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_pppoe, this, std::placeholders::_1, std::placeholders::_2 ) );
        raw_sock_ppp.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_ppp, this, std::placeholders::_1, std::placeholders::_2 ) );
        raw_sock_vlan.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_vlan, this, std::placeholders::_1, std::placeholders::_2 ) );
        
        periodic_callback.async_wait( std::bind( &EVLoop::periodic, this, std::placeholders::_1 ) );

        while( !interrupted ) {
            io.run();
        }
    }

    void generic_receive( boost::system::error_code ec, std::size_t len ) {
        if( !ec ) {
            std::vector<uint8_t> pkt { pktbuf.begin(), pktbuf.begin() + len };
            encapsulation_t encap { pkt };
            switch( encap.type ) {
            case ETH_PPPOE_DISCOVERY:
                if( auto const &error = pppoe::processPPPOE( pkt, encap ); !error.empty() ) {
                    log( error );
                }
                break;
            case ETH_PPPOE_SESSION:
                if( auto const &error = ppp::processPPP( pkt, encap ); !error.empty() ) {
                    log( error );
                }
                break;
            default:
                log( "Received packet with unknown ethertype: " + std::to_string( encap.type ) );
            }
        }
    }

    void receive_pppoe( boost::system::error_code ec, std::size_t len ) {
        generic_receive( ec, len );
        raw_sock_pppoe.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_pppoe, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void receive_ppp( boost::system::error_code ec, std::size_t len ) {
        generic_receive( ec, len );
        raw_sock_ppp.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_ppp, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void receive_vlan( boost::system::error_code ec, std::size_t len ) {
        generic_receive( ec, len );
        raw_sock_vlan.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_vlan, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void periodic( boost::system::error_code ec ) {
        if( interrupted ) {
            io.stop();
        }
        // Sending pppoe discovery packets
        while( !pppoe_outcoming.empty() ) {
            auto reply = pppoe_outcoming.pop();
            ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
            rep_eth->src_mac = runtime->hwaddr;
            raw_sock_pppoe.send( boost::asio::buffer( reply ) );
        }
        // Sending pppoe session control packets
        while( !ppp_outcoming.empty() ) {
            auto reply = ppp_outcoming.pop();
            raw_sock_ppp.send( boost::asio::buffer( reply ) );
        }
        periodic_callback.expires_from_now( boost::asio::chrono::seconds( 1 ) );
        periodic_callback.async_wait( std::bind( &EVLoop::periodic, this, std::placeholders::_1 ) );
    }
};