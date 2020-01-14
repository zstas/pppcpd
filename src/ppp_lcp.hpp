#ifndef PPP_LCP_H_
#define PPP_LCP_H_

#include "ppp_fsm.hpp"
#include "packet.hpp"

struct LCP_FSM: public PPP_FSM {

    LCP_FSM( uint16_t sid ):
        PPP_FSM( sid )
    {}

	std::string send_conf_req() override;
	std::string send_conf_ack( Packet &pkt ) override;
	std::string send_conf_nak( Packet &pkt ) override;
    std::string check_conf( Packet &pkt ) override;
	void send_conf_rej() override;
	void send_code_rej() override;
	void send_term_req() override;
	void send_term_ack() override;
};

#endif