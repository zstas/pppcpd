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

std::string std::to_string( const PPPOEDISC_HDR *hdr ) {
    std::ostringstream out;
    out << "discovery packet: ";
    out << "Type = " << hdr->type << " ";
    out << "Version = " << hdr->version << " ";
    out << "Code = ";
    switch( hdr->code ) {
        case PPPOE_CODE::PADI:
            out << "PADI "; break;
        case PPPOE_CODE::PADO:
            out << "PADO "; break;
        case PPPOE_CODE::PADR:
            out << "PADR "; break;
        case PPPOE_CODE::PADS:
            out << "PADS "; break;
        case PPPOE_CODE::PADT:
            out << "PADT "; break;
        default:
            out << "UNKNOWN ";
    }
    out << "Session id = " << hdr->session_id << " ";
    out << "length = " << htons( hdr->length );

    return out.str();
}