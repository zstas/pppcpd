#include <iostream>
#include <iomanip>

#include "string_helpers.hpp"
#include "runtime.hpp"
#include "packet.hpp"
#include "ethernet.hpp"

std::ostream& operator<<( std::ostream &stream, const PPP_FSM_STATE &state ) {
    switch( state ) {
    case PPP_FSM_STATE::Initial:    stream << "Initial"; break;
    case PPP_FSM_STATE::Starting:   stream << "Starting"; break;
    case PPP_FSM_STATE::Closed:     stream << "Closed"; break;
    case PPP_FSM_STATE::Stopped:    stream << "Stopped"; break;
    case PPP_FSM_STATE::Closing:    stream << "Closing"; break;
    case PPP_FSM_STATE::Stopping:   stream << "Stopping"; break;
    case PPP_FSM_STATE::Req_Sent:   stream << "Req_Sent"; break;
    case PPP_FSM_STATE::Ack_Rcvd:   stream << "Ack_Rcvd"; break;
    case PPP_FSM_STATE::Ack_Sent:   stream << "Ack_Sent"; break;
    case PPP_FSM_STATE::Opened:     stream << "Opened"; break;
    }

    return stream;
}

std::ostream& operator<<( std::ostream &stream, const PPPOEDISC_HDR &disc ) {
    stream << "discovery packet: ";
    stream << "Type = " << disc.type << " ";
    stream << "Version = " << disc.version << " ";
    stream << "Code = " << disc.code;
    stream << "Session id = " << disc.session_id << " ";
    stream << "length = " << bswap( disc.length );

    return stream;
}

std::ostream& operator<<( std::ostream &stream, const ETHERNET_HDR &eth ) {
    auto flags = stream.flags();
    stream << eth.src_mac << " -> " << eth.dst_mac;
    stream << " ethertype: " << std::hex << std::showbase <<std::setw(2) << bswap( eth.ethertype );
    stream.flags( flags );

    return stream;
}

std::ostream& operator<<( std::ostream &stream, const RADIUS_CODE &code ) {
    switch( code ) {
    case RADIUS_CODE::ACCESS_REQUEST: stream << "ACCESS_REQUEST"; break;
    case RADIUS_CODE::ACCESS_ACCEPT: stream << "ACCESS_ACCEPT"; break;
    case RADIUS_CODE::ACCESS_REJECT: stream << "ACCESS_REJECT"; break;
    case RADIUS_CODE::ACCOUNTING_REQUEST: stream << "ACCOUNTING_REQUEST"; break;
    case RADIUS_CODE::ACCOUNTING_RESPONSE: stream << "ACCOUNTING_RESPONSE"; break;
    case RADIUS_CODE::ACCESS_CHALLENGE: stream << "ACCESS_CHALLENGE"; break;
    case RADIUS_CODE::RESERVED: stream << "RESERVED"; break;
    }
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const RadiusPacket *pkt ) {
    stream << "Code: " << pkt->code;
    stream << " Id: " << static_cast<int>( pkt->id );
    stream << " Length: " << pkt->length.native();
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const pppoe_key_t &key ) {
    stream << "PPPoE Key: mac: " << key.mac << " session id: " << key.session_id << " outer vlan: " << key.outer_vlan << " inner vlan: " << key.inner_vlan;
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const pppoe_conn_t &conn ) {
    stream << "PPPoE Connection: mac: " << conn.mac << " cookie: " << conn.cookie << " outer vlan: " << conn.outer_vlan << " inner vlan: " << conn.inner_vlan;
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const mac_t &mac ) {
    char buf[ 18 ];
    snprintf( buf, sizeof( buf ), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    return stream << buf;
}

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
    uint8_t* payload = eth->data;
    auto eth_type = bswap( eth->ethertype );
    if( eth_type == ETH_VLAN ) {
        auto vlan = reinterpret_cast<VLAN_HDR*>( eth->data );
        stream << " vlan " << (int)( 0xFFF & bswap( vlan->vlan_id ) );
        payload = vlan->data;
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