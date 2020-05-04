#ifndef PPPOE_HPP_
#define PPPOE_HPP_

#include "packet.hpp"

namespace pppoe {
    uint8_t insertTag( std::vector<uint8_t> &pkt, PPPOE_TAG tag, const std::string &val );
    std::tuple<std::map<PPPOE_TAG,std::string>,std::string> parseTags( std::vector<uint8_t> &pkt );
    std::string processPPPOE( Packet inPkt );
}

struct pppoe_key {
    std::array<uint8_t,6> mac;
    uint16_t session_id;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
};

#endif