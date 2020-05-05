#ifndef PPP_H_
#define PPP_H_

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

namespace ppp {
    std::string processPPP( std::vector<uint8_t> &inPkt, const encapsulation_t &encap );
}

#endif