#include <iosfwd>
#include <array>
#include <vector>
#include <set>
#include <radiuspp.hpp>
#include "packet.hpp"

extern std::ostream& operator<<( std::ostream &stream, const ETHERNET_HDR &disc ); 

std::ostream& operator<<( std::ostream &stream, const PPPOE_CODE &code ) {
    switch( code ) {
    case PPPOE_CODE::PADI: stream << "PADI"; break;
    case PPPOE_CODE::PADO: stream << "PADO"; break;
    case PPPOE_CODE::PADR: stream << "PADR"; break;
    case PPPOE_CODE::PADS: stream << "PADS"; break;
    case PPPOE_CODE::PADT: stream << "PADT"; break;
    }
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const PPP_PROTO &code ) {
    switch( code ) {
    case PPP_PROTO::CHAP: stream << "CHAP"; break;
    case PPP_PROTO::IPCP: stream << "IPCP"; break;
    case PPP_PROTO::LCP: stream << "LCP"; break;
    case PPP_PROTO::IPV4: stream << "IPV4"; break;
    case PPP_PROTO::IPV6: stream << "IPV6"; break;
    case PPP_PROTO::IPV6CP: stream << "IPV6CP"; break;
    case PPP_PROTO::PAP: stream << "PAP"; break;
    case PPP_PROTO::LQR: stream << "LQR"; break;
    }
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const PacketPrint &pkt ) {
    auto eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    stream << *eth;
    uint8_t* payload = eth->getPayload();
    auto eth_type = bswap( eth->ethertype );
    if( eth_type == ETH_VLAN ) {
        auto vlan = reinterpret_cast<VLAN_HDR*>( eth->getPayload() );
        stream << " vlan " << (int)( 0xFFF & bswap( vlan->vlan_id ) );
        payload = vlan->getPayload();
        eth_type = bswap( vlan->ethertype );
    }

    if( eth_type == ETH_PPPOE_DISCOVERY ) {
        auto disc = reinterpret_cast<PPPOEDISC_HDR*>( payload );
        stream << " PPPoE Discovery: " << disc->code;
    } else if( eth_type == ETH_PPPOE_SESSION ) {
        auto sess = reinterpret_cast<PPPOESESSION_HDR*>( payload );
        stream << " PPPoE Session: " << bswap( sess->session_id ) << " proto: " << static_cast<PPP_PROTO>( bswap( sess->ppp_protocol ) );
    }

    return stream;
}