#ifndef PPP_H_
#define PPP_H_

#include "ppp_lcp.hpp"

enum class PPP_PROTO : uint16_t {
    IPV4 = 0x0021,
    IPV6 = 0x0057,
    IPV6CP = 0x8057,
    LCP = 0xc021,
    PAP = 0xc023,
    CHAP = 0xc223,
    IPCP = 0x8021,
    LQR = 0xc025,
};

template<typename T>
struct PPP_CP {
    T code;
    uint8_t identifier;
    uint16_t length;
}__attribute__((__packed__));

template<typename T, typename P>
struct PPP_CP_PAYLOAD {
    T code;
    uint8_t identifier;
    uint16_t length;
    P payload;
}__attribute__((__packed__));

namespace ppp {
    std::tuple<std::vector<uint8_t>,std::string> processPPP( std::vector<uint8_t> pkt );
    std::tuple<std::vector<uint8_t>,std::string> processLCP( PPP_CP<LCP_CODE> *lcp );
}

#endif