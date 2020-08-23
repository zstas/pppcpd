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
#include <fstream>
#include <tuple>

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
#include <boost/algorithm/string.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/ip/address_v4.hpp>

using namespace std::string_literals;
using io_service = boost::asio::io_service;
using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

// Local headers
#include "utils.hpp"
#include "net_integer.hpp"
#include "radius_avp.hpp"
#include "radius_dict.hpp"
#include "radius_packet.hpp"
#include "request_response.hpp"
#include "auth_client.hpp"
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
#include "ppp_chap.hpp"
#include "session.hpp"
#include "string_helpers.hpp"
#include "packet.hpp"
#include "aaa.hpp"
#include "config.hpp"
#include "vpp.hpp"
#include "runtime.hpp"
#include "evloop.hpp"
#include "yaml.hpp"
#include "cli.hpp"