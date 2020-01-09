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

template<typename T>
struct PPP_FSM {
    T protocol; // Here will be all protocol specific functions
    PPP_FSM_STATE state;
    uint8_t nak_counter { 0U };

    void receive( PPP_CP<LCP_CODE> *lcp );

    // Actions
	void layer_up();
	void layer_down();
	void layer_started();
	void layer_finished();

	int send_conf_req();
	void send_conf_ack();
	void send_conf_nak();
	void send_conf_rej();
	void send_code_rej();
	void send_term_req();
	void send_term_ack();

    // Events
    void recv_conf_req( PPP_CP<LCP_CODE> *lcp );
};

#endif