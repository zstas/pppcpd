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
    PPP_FSM_STATE state;

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
};