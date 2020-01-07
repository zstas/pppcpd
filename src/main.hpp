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
#include "session.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "tools.hpp"
#include "ppp_fsm.hpp"
#include "ppp.hpp"

using namespace std::string_literals;
std::tuple<std::vector<uint8_t>,std::string> dispatchPPPOE( std::vector<uint8_t> pkt );

struct PPPOEQ {
    std::mutex mutex;
    std::queue<std::vector<uint8_t>> queue;

    void push( std::vector<uint8_t> pkt ) {
        std::lock_guard lg( mutex );
        queue.push( pkt );
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
    
    // For dispatching control packets
    uint16_t lastSession = 0;

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
    std::map<uint8_t[8], uint8_t> pppoeSessions;
    std::shared_ptr<PPPOEPolicy> policy;
};