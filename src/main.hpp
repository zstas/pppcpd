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
            cond.wait( lg );
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
private:
    // For handling packets
    std::string ifName;

public:
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

    int PPPOEDiscFD { 0 };
    int PPPOESessFD { 0 };
    std::array<uint8_t,ETH_ALEN> hwaddr { 0 };
    std::set<uint16_t> sessionSet;
    std::map<uint16_t,PPPOESession> sessions;
    std::shared_ptr<PPPOEPolicy> pppoe_conf;
    std::shared_ptr<LCPPolicy> lcp_conf;
    std::shared_ptr<AAA> aaa;
    std::shared_ptr<VPPAPI> vpp;

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
extern std::atomic_bool interrupted;

class EVLoop {
private:
    boost::asio::io_context io;
    //boost::asio::signal_set signals{ io, SIGTERM, SIGINT };
    std::array<uint8_t,1500> pktbuf;

    boost::asio::generic::raw_protocol pppoed { PF_PACKET, htons( ETH_PPPOE_DISCOVERY ) };
    boost::asio::generic::raw_protocol pppoes { PF_PACKET, htons( ETH_PPPOE_SESSION ) };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_pppoe { io, pppoed };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_ppp { io, pppoes };
    boost::asio::steady_timer periodic_callback{ io, boost::asio::chrono::seconds( 1 ) };
public:
    EVLoop() {
        raw_sock_pppoe.async_receive( boost::asio::buffer( pktbuf ), [ &, this ]( boost::system::error_code ec, std::size_t len ) {
            if( !ec ) {
                pppoe_incoming.push( { pktbuf.begin(), pktbuf.begin() + len } );
            }
        });

        raw_sock_ppp.async_receive( boost::asio::buffer( pktbuf ), [ &, this ]( boost::system::error_code ec, std::size_t len ) {
            if( !ec ) {
                ppp_incoming.push( { pktbuf.begin(), pktbuf.begin() + len } );
            }
        });
        
        periodic_callback.async_wait( std::bind( &EVLoop::periodic, this, std::placeholders::_1 ) );

        while( !interrupted ) {
            io.run();
        }
    }

    void periodic( boost::system::error_code ec ) {
        log( "periodic callback" );
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