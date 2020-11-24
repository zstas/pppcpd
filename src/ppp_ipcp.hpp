#ifndef PPP_IPCP_H_
#define PPP_IPCP_H_

#include "ppp_fsm.hpp"

struct PPPOESession;

struct IPCP_FSM: public PPP_FSM {
	PPPOESession &session;

    IPCP_FSM( PPPOESession &s );

	FSM_RET send_conf_req() override;
	FSM_RET send_conf_ack( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_conf_nak( std::vector<uint8_t> &inPkt ) override;
    FSM_RET check_conf( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_conf_rej( std::vector<uint8_t> &rejected_options, uint8_t pkt_id ) override;
	FSM_RET send_code_rej() override;
	FSM_RET send_term_req() override;
	FSM_RET send_term_ack( std::vector<uint8_t> &inPkt ) override;
	FSM_RET send_echo_rep( std::vector<uint8_t> &inPkt ) override;
	FSM_RET recv_echo_rep( std::vector<uint8_t> &inPkt ) override;
};

#endif