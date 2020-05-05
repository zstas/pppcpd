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

using namespace std::string_literals;
using mac_t = std::array<uint8_t,6>;

extern std::atomic_bool interrupted;

class encapsulation_t {
    mac_t source_mac { 0, 0, 0, 0, 0, 0 };
    mac_t destination_mac { 0, 0, 0, 0, 0, 0 };
    uint16_t outer_vlan { 0 };
    uint16_t inner_vlan { 0 };
    uint16_t type;
public:
    encapsulation_t() = delete;

    encapsulation_t( std::vector<uint8_t> &pkt ) {
        if( pkt.size() < sizeof( ETHERNET_HDR ) ) {
            return;
        }

        ETHERNET_HDR *h = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
        std::copy( h->src_mac.begin(), h->src_mac.end(), source_mac );
        std::copy( h->dst_mac.begin(), h->dst_mac.end(), destination_mac );

        type = bswap16( h->ethertype );

        if( type == ETH_VLAN ) {
            VLAN_HDR *v = reinterpret_cast<VLAN_HDR*>( h->getPayload() );
            outer_vlan = 0x0FFF & bswap16( v->vlan_id );
            type = bswap16( v->ethertype );
            if( type == ETH_VLAN ) {
                v = reinterpret_cast<VLAN_HDR*>( v->getPayload() );
                inner_vlan = 0x0FFF & bswap16( v->vlan_id );
                type = bswap16( v->ethertype );
            }
        }
    }

    std::vector<uint8_t> generate_header( mac_t mac, uint16_t ethertype ) {
        std::vector<uint8_t> pkt;
        auto len = sizeof( ETHERNET_HDR );

        if( outer_vlan != 0 ) {
            len += sizeof( VLAN_HDR );
        }

        if( inner_vlan != 0 ) {
            len += sizeof( VLAN_HDR );
        }

        pkt.resize( len );
        ETHERNET_HDR *h = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );

        std::copy( mac.begin(), mac.end(), h->src_mac );
        std::copy( source_mac.begin(), source_mac.end(), h->dst_mac );
        
        if( outer_vlan == 0 ) {
            h->ethertype = bswap16( ethertype );
            return pkt;
        }

        h->ethertype = bswap16( ETH_VLAN );

        VLAN_HDR *v = reinterpret_cast<VLAN_HDR*>( h->getPayload() );
        v->vlan_id = bswap16( outer_vlan );
        if( inner_vlan == 0 ) {
            v->ethertype = bswap16( ethertype );
            return pkt;
        }

        v->ethertype = bswap16( ETH_VLAN );
        v = reinterpret_cast<VLAN_HDR*>( v->getPayload() );
        v->vlan_id = bswap16( inner_vlan );
        v->ethertype = bswap16( ethertype );

        return pkt;
    }
};

class pppoe_conn_t {
    mac_t mac;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
    std::string cookie;
public:
    pppoe_conn_t() = delete;
    pppoe_conn_t( mac_t m, uint16_t o, uint16_t i, std::string c ):
        mac( m ),
        outer_vlan( o ),
        inner_vlan( i ),
        cookie( std::move( c ) )
    {}
};

class pppoe_key_t {
    mac_t mac;
    uint16_t session_id;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
public:
    pppoe_key_t() = delete;
    pppoe_key_t( mac_t m, uint16_t s, uint16_t o, uint16_t i ):
        mac( m ),
        session_id( s ),
        outer_vlan( o ),
        inner_vlan( i )
    {}
};

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

struct PPPOERuntime {
    PPPOERuntime() = delete;
    PPPOERuntime( const PPPOERuntime& ) = delete;
    PPPOERuntime( PPPOERuntime&& ) = default;
    PPPOERuntime( std::string name ) : 
        ifName( std::move( name ) )
    {}

    PPPOERuntime operator=( const PPPOERuntime& ) = delete;
    PPPOERuntime& operator=( PPPOERuntime&& ) = default;

    std::string setupPPPOEDiscovery();
    std::string setupPPPOESession();

    std::string ifName;
    std::array<uint8_t,ETH_ALEN> hwaddr { 0 };
    std::set<uint16_t> sessionSet;
    std::map<uint16_t,PPPOESession> sessions;
    std::shared_ptr<PPPOEPolicy> pppoe_conf;
    std::shared_ptr<LCPPolicy> lcp_conf;
    std::shared_ptr<AAA> aaa;
    std::shared_ptr<VPPAPI> vpp;

    std::set<pppoe_conn_t> pendingSession;
    std::map<pppoe_key_t,uint16_t> activeSessions;

    // TODO: create periodic callback which will be clearing pending sessions
    std::string pendeSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie ) {
        pppoe_conn_t key { mac, outer_vlan, inner_vlan, cookie };

        if( auto const &[it, ret ] = pendingSession.emplace( key ); !ret ) {
            return { "Cannot allocate new Pending session" };
        }
        return {};
    }

    bool checkSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie ) {
        pppoe_conn_t key { mac, outer_vlan, inner_vlan, cookie };

        if( auto const &it = pendingSession.find( key ); it != pendingSession.end() ) {
            pendingSession.erase( it );
            return true;
        }
        return false;
    }

    std::tuple<uint16_t,std::string> allocateSession( std::array<uint8_t,6> mac ) {
        for( uint16_t i = 1; i < UINT16_MAX; i++ ) {
            if( auto ret = sessionSet.find( i ); ret == sessionSet.end() ) {
                if( auto const &[ it, ret ] = sessionSet.emplace( i ); !ret ) {
                    return { 0, "Cannot allocate session: cannot emplace value in set" };
                }
                if( auto const &[ it, ret ] = sessions.emplace( i, PPPOESession{ mac, i }); !ret ) {
                    return { 0, "Cannot allocate session: cannot emplace new PPPOESession" };
                }
                return { i, "" };
            }
        }
        return { 0, "Maximum of sessions" };
    }

    std::string deallocateSession( std::array<uint8_t,6> mac, uint16_t sid ) {
        auto const &it = sessions.find( sid );
        if( it == sessions.end() ) {
            return "Cannot find session with this session id";
        }

        if( it->second.mac != mac ) {
            return "Wrong mac!";
        }

        sessions.erase( it );
        return "";
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

    void receive_pppoe( boost::system::error_code ec, std::size_t len ) {
        if( !ec ) {
            std::vector<uint8_t> pkt { pktbuf.begin(), pktbuf.begin() + len };
            if( auto const &error = pppoe::processPPPOE( pkt ); !error.empty() ) {
                log( error );
            }
        }
        raw_sock_pppoe.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_pppoe, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void receive_ppp( boost::system::error_code ec, std::size_t len ) {
        if( !ec ) {
            std::vector<uint8_t> pkt { pktbuf.begin(), pktbuf.begin() + len };
            if( auto const &error = ppp::processPPP( pkt ); !error.empty() ) {
                log( error );
            }
        }
        raw_sock_ppp.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_ppp, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void receive_vlan( boost::system::error_code ec, std::size_t len ) {
        if( !ec ) {
            std::vector<uint8_t> pkt { pktbuf.begin(), pktbuf.begin() + len };
            if( auto const &error = ppp::processPPP( pkt ); !error.empty() ) {
                log( error );
            }
        }
        raw_sock_vlan.async_receive( boost::asio::buffer( pktbuf ), std::bind( &EVLoop::receive_vlan, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    std::string receive_packet( std::vector<uint8_t> pkt ) {
        uint16_t outer_vlan = 0;
        uint16_t inner_vlan = 0;
        uint16_t type;
        uint8_t len_to_strip = 0;

        ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
        type = bswap16( eth->ethertype );
        len_to_strip += sizeof( *eth );
        if( type == ETH_VLAN ) {
            VLAN_HDR *vlan = reinterpret_cast<VLAN_HDR*>( eth->getPayload() );
            outer_vlan = bswap16( vlan->vlan_id & 0xFF0F );
            type = bswap16( vlan->ethertype );
            len_to_strip += sizeof( *vlan );
            if( type == ETH_VLAN ) {
                vlan = reinterpret_cast<VLAN_HDR*>( vlan->getPayload() );
                inner_vlan = bswap16( vlan->vlan_id & 0xFF0F );
                type = bswap16( vlan->ethertype );
                len_to_strip += sizeof( *vlan );
            }
        }

        if( pkt.size() < len_to_strip ) {
            return "Packet to small to process";
        }
        pkt.erase( pkt.begin(), pkt.begin() + len_to_strip );

        switch( type ) {
        case ETH_PPPOE_DISCOVERY:
            if( auto const &error = pppoe::processPPPOE( pkt ); !error.empty() ) {
                return error;
            }
            break;
        case ETH_PPPOE_SESSION:
        if( auto const &error = ppp::processPPP( pkt ); !error.empty() ) {
                return error;
            }
            break;
        default:
            return "Wrong ethertype for this service";
        }
        return {};
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