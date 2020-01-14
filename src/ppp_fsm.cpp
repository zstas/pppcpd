#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

void PPP_FSM::receive( Packet &pkt ) {
    log( "receive pkt in state: " + std::to_string( state ) );
    if( pkt.lcp == nullptr ) {
        return;
    }

    if( state == PPP_FSM_STATE::Initial || 
        state == PPP_FSM_STATE::Starting ) {
            log( "Received packet in invalid state: "s + std::to_string( state ) );
            return;
    }
    
    switch( pkt.lcp->code ) {
    case LCP_CODE::CONF_REQ:
        if( auto const &err = recv_conf_req( pkt ); !err.empty() ) {
            log( "Error while receiving LCP packet CONF_REQ: " + err );
        }
        break;
    case LCP_CODE::CONF_ACK:
        if( auto const &err = recv_conf_ack( pkt ); !err.empty() ) {
            log( "Error while receiving LCP packet CONF_ACK: " + err );
        }
	    break;
    
    case LCP_CODE::CONF_NAK:
    case LCP_CODE::CONF_REJ:
	    //fsm_rconfnakrej(f, code, id, inp, len);
	    break;
    
    case LCP_CODE::TERM_REQ:
	    //fsm_rtermreq(f, id, inp, len);
	    break;
    
    case LCP_CODE::TERM_ACK:
	    //fsm_rtermack(f);
	    break; 
    
    case LCP_CODE::CODE_REJ:
        //fsm_rcoderej
        break;
    default:
        //send CODEREJ
        break;
    }
    log( "FSM state: " + std::to_string( state ) );
}

std::string PPP_FSM::recv_conf_req( Packet &pkt ) {
    log( "recv_conf_req current state: " + std::to_string( state ) );
    switch( state ){
    case PPP_FSM_STATE::Closing:
    case PPP_FSM_STATE::Stopping:
        return "We're stopping or closing right now";
    case PPP_FSM_STATE::Closed:
        // send TERM ACK
        return "Receive conf req in closed state";
    case PPP_FSM_STATE::Opened:
        // Restart connection
        layer_down();
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    case PPP_FSM_STATE::Stopped:
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    default:
        break;
    }

    return check_conf( pkt );
}

void PPP_FSM::layer_up() {
    switch( state ) {
    case PPP_FSM_STATE::Initial:
	    state = PPP_FSM_STATE::Closed;
	    break;

    case PPP_FSM_STATE::Starting:
	    if( auto err = send_conf_req(); !err.empty() ) {
            log( "Cannot set layer up: " + err );
        } else {
	        state = PPP_FSM_STATE::Req_Sent;
        }
	    break;

    default:
        break;
    }
}

void PPP_FSM::layer_down() {
    return;
}

void PPP_FSM::open() {
    switch( state ) {
    case PPP_FSM_STATE::Initial:
        state = PPP_FSM_STATE::Starting;
        //starting()
        break;
    case PPP_FSM_STATE::Closed:
        if( auto err = send_conf_req(); !err.empty() ) {
            log( "Cannot set layer up: " + err );
        } else {
	        state = PPP_FSM_STATE::Req_Sent;
        }
        break;
    case PPP_FSM_STATE::Closing:
        state = PPP_FSM_STATE::Stopping;
    case PPP_FSM_STATE::Stopped:
    case PPP_FSM_STATE::Opened:
        // If restart
        break;
    default:
        break;
    }
}

std::string PPP_FSM::recv_conf_ack( Packet &pkt ) {
    log( "recv_conf_ack current state: " + std::to_string( state ) );

    // Parse in case of moved data
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );

    if( pkt.lcp->identifier != pkt_id ) {
        return "Packet identifier is not match with our";
    }

    seen_ack = true;

    switch( state ) {
    case PPP_FSM_STATE::Closed:
    case PPP_FSM_STATE::Stopped:
        // send TERM ACK
        break;
    case PPP_FSM_STATE::Req_Sent:
        state = PPP_FSM_STATE::Ack_Rcvd;
        break;
    case PPP_FSM_STATE::Ack_Rcvd:
        log( "extra ack, but not considering it is like a problem" );
        break;
    case PPP_FSM_STATE::Ack_Sent:
        state = PPP_FSM_STATE::Opened;
        break;
    case PPP_FSM_STATE::Opened:
        // Restarting the connection
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    default:
        log( "Incorrect state?" );
        break;
    }

    return "";
}