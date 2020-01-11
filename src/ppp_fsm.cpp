#include "main.hpp"

void PPP_FSM::receive( PPP_LCP *lcp ) {
    if( state == PPP_FSM_STATE::Initial || 
        state == PPP_FSM_STATE::Starting ) {
            log( "Received packet in invalid state: "s + std::to_string( state ) );
            return;
    }
    
    switch( lcp->code ) {
    case LCP_CODE::CONF_REQ:
        recv_conf_req( lcp );
        break;
    case LCP_CODE::CONF_ACK:
        //fsm_rconfack(f, id, inp, len);
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
}

void PPP_FSM::recv_conf_req( PPP_LCP *lcp ) {
    switch( state ){
    case PPP_FSM_STATE::Closing:
    case PPP_FSM_STATE::Stopping:
        return;
    case PPP_FSM_STATE::Closed:
        // send TERM ACK
        return;
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

    //code = reqci
    LCP_CODE code = LCP_CODE::CONF_ACK;
    //send pkt
    if( code == LCP_CODE::CONF_ACK ) {
        if( state == PPP_FSM_STATE::Ack_Rcvd ) {
            state = PPP_FSM_STATE::Opened;
            layer_up();
        } else {
            state = PPP_FSM_STATE::Ack_Sent;
        }
        nak_counter = 0;
    } else {
        if( state != PPP_FSM_STATE::Ack_Rcvd ) {
            state = PPP_FSM_STATE::Req_Sent;
        }
        if( code == LCP_CODE::CONF_NAK ) {
            nak_counter++;
        }
    }
}

int PPP_FSM::send_conf_req() {
    return 1;
}

void PPP_FSM::layer_up() {
    return;
}

void PPP_FSM::layer_down() {
    return;
}