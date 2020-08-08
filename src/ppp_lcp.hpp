#ifndef PPP_LCP_H_
#define PPP_LCP_H_

#include "ppp_fsm.hpp"

struct PPPOESession;

struct LCP_FSM: public PPP_FSM {
	PPPOESession &session;

    LCP_FSM( PPPOESession &s );

	FSM_RET send_conf_req() override;
	FSM_RET send_conf_ack( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_conf_nak( std::vector<uint8_t> &inPkt ) override;
    FSM_RET check_conf( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_conf_rej() override;
	FSM_RET send_code_rej() override;
	FSM_RET send_term_req() override;
	FSM_RET send_term_ack( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_echo_rep( std::vector<uint8_t> &inPkt );
};

#endif