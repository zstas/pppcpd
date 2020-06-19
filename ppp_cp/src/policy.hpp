#ifndef POLICY_HPP
#define POLICY_HPP

struct PPPOEPolicy {
    std::string ac_name { "pppoecpd" };
    std::vector<std::string> service_name { "internet" };
    bool insert_cookie { false };
    bool ignore_service_name { false };
};

struct LCPPolicy {
    bool insertMagicNumber { true };
    uint16_t MRU { 1492U };
    bool authCHAP { false };
    bool authPAP { true };
};

#endif