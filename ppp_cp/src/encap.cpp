#include "main.hpp"

encapsulation_t::encapsulation_t( std::vector<uint8_t> &pkt ) {
    if( pkt.size() < sizeof( ETHERNET_HDR ) ) {
        return;
    }

    auto len = sizeof( ETHERNET_HDR );

    ETHERNET_HDR *h = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    std::copy( h->src_mac.begin(), h->src_mac.end(), source_mac.begin() );
    std::copy( h->dst_mac.begin(), h->dst_mac.end(), destination_mac.begin() );

    type = bswap16( h->ethertype );

    if( type == ETH_VLAN ) {
        VLAN_HDR *v = reinterpret_cast<VLAN_HDR*>( h->getPayload() );
        outer_vlan = 0x0FFF & bswap16( v->vlan_id );
        type = bswap16( v->ethertype );
        len += sizeof( VLAN_HDR );
        if( type == ETH_VLAN ) {
            v = reinterpret_cast<VLAN_HDR*>( v->getPayload() );
            inner_vlan = 0x0FFF & bswap16( v->vlan_id );
            type = bswap16( v->ethertype );
            len += sizeof( VLAN_HDR );
        }
    }

    pkt.erase( pkt.begin(), pkt.begin() + len );
}

std::vector<uint8_t> encapsulation_t::generate_header( mac_t mac, uint16_t ethertype ) const {
    std::vector<uint8_t> pkt;
    auto len = sizeof( ETHERNET_HDR );

    if( outer_vlan != 0 ) {
        len += sizeof( VLAN_HDR );
    }

    if( inner_vlan != 0 ) {
        len += sizeof( VLAN_HDR );
    }

    pkt.resize( len );
    ETHERNET_HDR *h = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );

    std::copy( mac.begin(), mac.end(), h->src_mac.begin() );
    std::copy( source_mac.begin(), source_mac.end(), h->dst_mac.begin() );
        
    if( outer_vlan == 0 ) {
        h->ethertype = bswap16( ethertype );
        return pkt;
    }

    h->ethertype = bswap16( ETH_VLAN );

    VLAN_HDR *v = reinterpret_cast<VLAN_HDR*>( h->getPayload() );
    v->vlan_id = bswap16( outer_vlan );
    if( inner_vlan == 0 ) {
        v->ethertype = bswap16( ethertype );
        return pkt;
    }

    v->ethertype = bswap16( ETH_VLAN );
    v = reinterpret_cast<VLAN_HDR*>( v->getPayload() );
    v->vlan_id = bswap16( inner_vlan );
    v->ethertype = bswap16( ethertype );

    return pkt;
}

bool encapsulation_t::operator!=( const encapsulation_t &r ) const {
    return !operator==( r );
}

bool encapsulation_t::operator==( const encapsulation_t &r ) const {
    return  ( source_mac == r.source_mac ) && 
            ( destination_mac == r.destination_mac ) &&
            ( outer_vlan == r.outer_vlan ) &&
            ( inner_vlan == r.inner_vlan ) &&
            ( type == r.type );
}