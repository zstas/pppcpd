#ifndef ETHERNET_HPP_
#define ETHERNET_HPP_

struct ETHERNET_HDR {
    std::array<uint8_t,6> dst_mac;
    std::array<uint8_t,6> src_mac;
    uint16_t ethertype;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));;

static_assert( sizeof( ETHERNET_HDR ) == 14 );

struct VLAN_HDR {
    uint16_t vlan_id;
    uint16_t ethertype;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));;

static_assert( sizeof( VLAN_HDR ) == 4 );

#endif