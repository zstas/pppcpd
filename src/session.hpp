struct PPPOESession {
    // General Data
    std::array<uint8_t,6> mac;

    // PPPoE Data
    uint16_t session_id;
    std::string cookie;

    // PPP FSM for all the protocols we support
    LCP_FSM lcp;
    PPP_AUTH auth;
    LCP_FSM ipcp;

    // LCP negotiated options
    uint16_t our_MRU;
    uint16_t peer_MRU;
    uint32_t our_magic_number;
    uint32_t peer_magic_number;

    PPPOESession( std::array<uint8_t,6> m, uint16_t sid ): 
        mac( m ),
        session_id( sid ),
        lcp( sid),
        auth( sid ),
        ipcp( sid )
    {
        log( "Session UP: " + std::to_string( sid ) );
    }
};