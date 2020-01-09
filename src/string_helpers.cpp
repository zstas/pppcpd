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

