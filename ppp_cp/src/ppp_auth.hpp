#ifndef PPP_AUTH_HPP_
#define PPP_AUTH_HPP_

struct PPP_AUTH {
private:
    uint16_t session_id;
    uint8_t pkt_id { 1U };

public:

    PPP_AUTH( uint16_t sid ):
        session_id( sid )
    {}
    
    void open();
    void layer_up();
    void layer_down();

    FSM_RET receive( Packet &pkt );
    // PAP methods
    FSM_RET recv_auth_req( Packet &pkt );
    FSM_RET send_auth_ack( Packet &pkt );
    FSM_RET send_auth_nak( Packet &pkt );
};

#endif