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

// Local headers
#include "pppoe.hpp"
#include "ethernet.hpp"
#include "session.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "tools.hpp"

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