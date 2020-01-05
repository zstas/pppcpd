#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

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

using namespace std::string_literals;
std::tuple<PPPOEDISC_HDR,std::string> dispatchPPPOE( std::array<uint8_t,6> mac, PPPOEDISC_HDR *inPkt );
