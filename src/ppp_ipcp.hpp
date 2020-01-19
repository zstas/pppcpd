#ifndef PPP_IPCP_H_
#define PPP_IPCP_H_

#include "ppp_fsm.hpp"
#include "packet.hpp"

struct IPCP_FSM: public PPP_FSM {

    IPCP_FSM( uint16_t sid ):
        PPP_FSM( sid )
    {}

	FSM_RET send_conf_req() override;
	FSM_RET send_conf_ack( Packet &pkt ) override;
	FSM_RET send_conf_nak( Packet &pkt ) override;
    FSM_RET check_conf( Packet &pkt ) override;
	FSM_RET send_conf_rej() override;
	FSM_RET send_code_rej() override;
	FSM_RET send_term_req() override;
	FSM_RET send_term_ack() override;
	FSM_RET send_echo_rep( Packet &pkt ) override;
};

#endif