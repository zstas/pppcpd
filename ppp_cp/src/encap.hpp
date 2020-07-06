#ifndef ENCAP_HPP
#define ENCAP_HPP

#include "packet.hpp"

class encapsulation_t {
public:
    mac_t source_mac { 0, 0, 0, 0, 0, 0 };
    mac_t destination_mac { 0, 0, 0, 0, 0, 0 };
    uint16_t outer_vlan { 0 };
    uint16_t inner_vlan { 0 };
    uint16_t type;
    encapsulation_t() = delete;

    encapsulation_t( std::vector<uint8_t> &pkt, uint16_t outer_vlan, uint16_t inner_vlan );
    std::vector<uint8_t> generate_header( mac_t mac, uint16_t ethertype ) const;
    bool operator==( const encapsulation_t &r ) const;
    bool operator!=( const encapsulation_t &r ) const;
};

#endif