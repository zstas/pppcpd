#include <iostream>
#include <iomanip>

#include "string_helpers.hpp"

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
    stream << " Id: " << pkt->id;
    stream << " Length: " << pkt->length.native();
    return stream;
}