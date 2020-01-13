#ifndef PPP_AUTH_HPP_
#define PPP_AUTH_HPP_

struct PPP_AUTH {
private:
    uint8_t pkt_id { 1U };

public:

    void receive( Packet pkt );
    // PAP methods
    void recv_auth_req( Packet pkt );
    void send_auth_ack();
    void send_auth_nak();
};

#endif