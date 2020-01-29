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

// Network api
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <poll.h>

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
    std::queue<std::vector<uint8_t>> queue;

    void push( std::vector<uint8_t> pkt ) {
        std::lock_guard lg( mutex );
        queue.push( std::move( pkt ) );
    }

    std::vector<uint8_t> pop() {
        std::lock_guard lg( mutex );
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