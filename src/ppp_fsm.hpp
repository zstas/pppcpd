#ifndef PPP_FSM_HPP_
#define PPP_FSM_HPP_

enum class PPP_FSM_STATE : uint8_t {
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

    void receive( Packet &pkt );
    void open();

    // Actions
	void layer_up();
	void layer_down();
	void layer_started();
	void layer_finished();

    // Events
    std::string recv_conf_req( Packet &pkt );
    std::string recv_conf_ack( Packet &pkt );

    //Overrided
	virtual std::string send_conf_req() = 0;
	virtual std::string send_conf_ack( Packet &pkt ) = 0;
	virtual std::string send_conf_nak( Packet &pkt ) = 0;
    virtual std::string check_conf( Packet &pkt ) = 0;
	virtual void send_conf_rej() = 0;
	virtual void send_code_rej() = 0;
	virtual void send_term_req() = 0;
	virtual void send_term_ack() = 0;
};

#endif