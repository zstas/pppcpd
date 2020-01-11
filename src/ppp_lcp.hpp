#ifndef PPP_LCP_H_
#define PPP_LCP_H_

enum class LCP_OPTIONS: uint8_t {
    VEND_SPEC = 0,
    MRU = 1,
    AUTH_PROTO = 3,
    QUAL_PROTO = 4,
    MAGICK_NUMBER = 5,
    PROTO_FIELD_COMP = 7,
    ADD_AND_CTRL_FIELD_COMP = 8,
};

struct LCP {
    std::tuple<Packet,std::string> processReq();
};

struct IPCP {
    std::tuple<Packet,std::string> processReq();
};

#endif