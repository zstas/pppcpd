#include <iosfwd>
#include <array>
#include <vector>
#include <set>
#include <radiuspp.hpp>
#include "packet.hpp"

std::ostream& operator<<( std::ostream &stream, Packet &pkt ) {
    auto eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    stream << eth->src_mac << " -> " << eth->dst_mac;
    uint8_t* payload = eth->getPayload();
    auto eth_type = bswap( eth->ethertype );
    if( eth_type == ETH_VLAN ) {
        auto vlan = reinterpret_cast<VLAN_HDR*>( eth->getPayload() );
        stream << " vlan " << std::hex << ( 0xFFF & bswap( vlan->vlan_id ) );
        payload = vlan->getPayload();
        eth_type = bswap( vlan->ethertype );
    }



    return stream;
}