#ifndef PPP_FSM_HPP_
#define PPP_FSM_HPP_

enum class PPP_FSM_STATE: uint8_t {
    Initial = 0,
    Starting,
    Closed,
    Stopped,
    Closing,
    Stopping,
    Req_Sent,
    Ack_Rcvd,
    Ack_Sent,
    Opened
};

enum class PPP_FSM_ACTION: uint8_t {
    NONE,
    LAYER_UP,
    LAYER_DOWN
};

using FSM_RET = std::tuple<PPP_FSM_ACTION,std::string>;

struct PPP_FSM {
protected:
    PPP_FSM_STATE state { PPP_FSM_STATE::Initial };
    uint8_t nak_counter { 0U };
    uint16_t session_id { 0U };
    uint8_t pkt_id { 1U };

    bool seen_ack { false };
public:

    PPP_FSM( uint16_t sid ):
        session_id( sid )
    {}

    FSM_RET receive( Packet &pkt );
    void open();

    // Actions
	void layer_up();
	void layer_down();
	void layer_started();
	void layer_finished();

    // Events
    FSM_RET recv_conf_req( Packet &pkt );
    FSM_RET recv_conf_ack( Packet &pkt );
    FSM_RET recv_term_req( Packet &pkt );

    //Overrided
	virtual FSM_RET send_conf_req() = 0;
	virtual FSM_RET send_conf_ack( Packet &pkt ) = 0;
	virtual FSM_RET send_conf_nak( Packet &pkt ) = 0;
    virtual FSM_RET check_conf( Packet &pkt ) = 0;
	virtual FSM_RET send_conf_rej() = 0;
	virtual FSM_RET send_code_rej() = 0;
	virtual FSM_RET send_term_req() = 0;
	virtual FSM_RET send_term_ack( Packet &pkt ) = 0;
    virtual FSM_RET send_echo_rep( Packet &pkt ) = 0;
};

#endif