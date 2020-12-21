#include <iostream>
#include <iomanip>
#include <boost/asio/ip/address_v4.hpp>

#include "string_helpers.hpp"
#include "runtime.hpp"
#include "packet.hpp"
#include "ethernet.hpp"
#include "cli.hpp"
#include "vpp_types.hpp"

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

std::ostream& operator<<( std::ostream &stream, const PPPOESession &session ) {
    stream << std::setw( 6 ) << std::setfill( ' ' ) << std::left << session.session_id;
    stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << session.encap.destination_mac;
    stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << session.username;
    stream << std::setw( 20 ) << std::setfill( ' ' ) << std::left << address_v4_t( session.address );
    return stream;
}

std::ostream& operator<<( std::ostream &os, const GET_PPPOE_SESSION_RESP &val ) {
    auto flags = os.flags();
    os << std::left;
    os << " ";
    os << std::setw( 10 ) << "AAA SID";
    os << std::setw( 10 ) << "SessID";
    os << std::setw( 10 ) << "Cookie";
    os << std::setw( 20 ) << "Username";
    os << std::setw( 20 ) << "Address";
    os << std::setw( 10 ) << "Ifindex";
    os << std::setw( 10 ) << "VRF";
    os << std::setw( 10 ) << "Unnumbered";
    os << std::endl;
    for( auto const &sess: val.sessions ) {
        os << std::setw( 10 ) << sess.aaa_session_id;
        os << std::setw( 10 ) << sess.session_id;
        os << std::setw( 10 ) << sess.cookie;
        os << std::setw( 20 ) << sess.username;
        os << std::setw( 20 ) << boost::asio::ip::make_address_v4( sess.address ).to_string();
        os << std::setw( 10 ) << sess.ifindex;
        os << std::setw( 10 ) << sess.vrf;
        os << std::setw( 10 ) << sess.unnumbered;
        os << std::endl;
    }

    os.flags( flags );
    return os;
}

std::ostream& operator<<( std::ostream &os, const GET_VPP_IFACES_RESP &resp ) {
    auto flags = os.flags();
    os << std::left;
    os << " ";
    os << std::setw( 6 ) << "Ifx";
    os << std::setw( 30 ) << "Name";
    os << std::setw( 10 ) << "Device";
    os << std::setw( 20 ) << "MAC";
    os << std::setw( 10 ) << "MTU";
    os << std::setw( 10 ) << "Speed";
    os << std::setw( 10 ) << "Type";
    os << std::endl;
    for( auto const &iface: resp.ifaces ) {
        os << std::setw( 6 ) << iface.sw_if_index;
        os << std::setw( 30 ) << iface.name;
        os << std::setw( 10 ) << iface.device;
        os << std::setw( 20 ) << iface.mac;
        os << std::setw( 10 ) << iface.mtu;
        os << std::setw( 10 ) << iface.speed;
        os << std::setw( 10 ) << iface.type;
        os << std::endl;
    }

    os.flags( flags );
    return os;
}

std::ostream& operator<<( std::ostream &stream, const IfaceType &iface ) {
    switch( iface ) {
    case IfaceType::HW_IFACE: stream << "HW_IFACE"; break;
    case IfaceType::LOOPBACK: stream << "LOOPBACK"; break;
    case IfaceType::TAP: stream << "TAP"; break;
    case IfaceType::SUBIF: stream << "SUBIF"; break;
    default: stream << "UNKNOWN"; break;
    }
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const struct VPPInterface &iface ) {
    stream << "VPP interface " << iface.name;
    stream << "; Device: " << iface.device;
    stream << "; mac: " << iface.mac;
    stream << "; ifindex: " << iface.sw_if_index;
    stream << "; speed: " << iface.speed;
    stream << "; MTU: " << iface.mtu;
    stream << "; type: " << iface.type;
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const struct VPPIfaceCounters &ctr ) {
    stream << std::dec;
    stream << "Drops:  " << ctr.drops;
    stream << " TxPkts: " << ctr.txPkts;
    stream << " TxBytes: " << ctr.txBytes;
    stream << " RxPkts: " << ctr.rxPkts;
    stream << " RxBytes: " << ctr.rxBytes;
    return stream;
}

std::ostream& operator<<( std::ostream &os, const GET_VERSION_RESP &resp ) {
    os << "Version: " << resp.version_string;
    return os;
}

std::ostream& operator<<( std::ostream &os, const GET_AAA_SESSIONS_RESP &resp ) {
    auto flags = os.flags();
    os << std::left;
    os << " ";
    os << std::setw( 6 ) << "SID";
    os << std::setw( 16 ) << "Username";
    os << std::setw( 16 ) << "Address";
    os << std::setw( 16 ) << "DNS1";
    os << std::setw( 16 ) << "DNS2";
    os << std::setw( 16 ) << "FramedPool";
    os << std::setw( 16 ) << "Unnumbered";
    os << std::setw( 16 ) << "VRF";
    os << std::endl;
    for( auto const &iface: resp.sessions ) {
        os << std::setw( 6 ) << iface.session_id;
        os << std::setw( 16 ) << iface.username;
        os << std::setw( 16 ) << iface.address;
        os << std::setw( 16 ) << iface.dns1;
        os << std::setw( 16 ) << iface.dns2;
        os << std::setw( 16 ) << iface.framed_pool;
        os << std::setw( 16 ) << iface.unnumbered;
        os << std::setw( 16 ) << iface.vrf;
        os << std::endl;
    }

    os.flags( flags );
    return os;
}