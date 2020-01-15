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
    
    void receive( Packet &pkt );
    // PAP methods
    void recv_auth_req( Packet &pkt );
    std::string send_auth_ack( Packet &pkt );
    std::string send_auth_nak( Packet &pkt );
};

#endif