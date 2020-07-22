#include "main.hpp"

std::string std::to_string( PPP_FSM_STATE state ) {
    switch( state ) {
    case PPP_FSM_STATE::Initial:
        return "Initial";
    case PPP_FSM_STATE::Starting:
        return "Starting";
    case PPP_FSM_STATE::Closed:
        return "Closed";
    case PPP_FSM_STATE::Stopped:
        return "Stopped";
    case PPP_FSM_STATE::Closing:
        return "Closing";
    case PPP_FSM_STATE::Stopping:
        return "Stopping";
    case PPP_FSM_STATE::Req_Sent:
        return "Req_Sent";
    case PPP_FSM_STATE::Ack_Rcvd:
        return "Ack_Rcvd";
    case PPP_FSM_STATE::Ack_Sent:
        return "Ack_Sent";
    case PPP_FSM_STATE::Opened:
        return "Opened";
    }
    return "Unknown state";
}

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
    stream << "length = " << bswap16( disc.length );

    return stream;
}

std::string std::to_string( ETHERNET_HDR *eth ) {
    std::ostringstream out;
    out << "dst mac: ";
    for( auto const &el: eth->dst_mac) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out.seekp( -1, std::ios::end );
    out << std::endl;
    out << "src mac: ";
    for( auto const &el: eth->src_mac) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out.seekp( -1, std::ios::end );
    out << std::endl;
    out << "ethertype: 0x" << std::hex << std::setw(2) << htons( eth->ethertype ) << std::endl;

    return out.str();
}