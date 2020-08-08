#ifndef PPP_H_
#define PPP_H_

namespace ppp {
    std::string processPPP( std::vector<uint8_t> &inPkt, const encapsulation_t &encap );
}

#endif