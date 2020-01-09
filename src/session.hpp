struct PPPOESession {
    // General Data
    uint8_t mac[6];

    // PPPoE Data
    uint16_t session_id;
    std::string cookie;

    // PPP FSM for all the protocols we support
    PPP_FSM<LCP> lcp;
};