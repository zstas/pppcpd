struct PPPOEPolicy {
    std::string ac_name { "pppoecpd" };
    std::string service_name { "internet" };
    bool insertCookie { false };
    bool ignoreServiceName { false };
};

struct LCPPolicy {
    bool insertMagicNumber { true };
    uint16_t MRU { 1492U };
    bool authCHAP { false };
    bool authPAP { true };
};