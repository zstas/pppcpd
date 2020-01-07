struct PPPOESession {
    uint8_t mac[6];
    uint16_t session_id;
    bool started;

    std::string cookie;
};