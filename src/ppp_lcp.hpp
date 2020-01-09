#ifndef PPP_LCP_H_
#define PPP_LCP_H_

enum class LCP_CODE : uint8_t {
    VENDOR_SPECIFIC = 0,
    CONF_REQ = 1,
    CONF_ACK = 2,
    CONF_NAK = 3,
    CONF_REJ = 4,
    TERM_REQ = 5,
    TERM_ACK = 6,
    CODE_REJ = 7,
    PROTO_REJ = 8,
    ECHO_REQ = 9,
	ECHO_REPLY = 10,
	DISCARD_REQ = 11,
	IDENTIFICATION = 12,
	TIME_REMAINING = 13,
};

enum class LCP_OPTIONS: uint8_t {
    VEND_SPEC = 0,
    MRU = 1,
    AUTH_PROTO = 3,
    QUAL_PROTO = 4,
    MAGICK_NUMBER = 5,
    PROTO_FIELD_COMP = 7,
    ADD_AND_CTRL_FIELD_COMP = 8,
};

template<typename T>
struct PPP_CP {
    T code;
    uint8_t identifier;
    uint16_t length;
}__attribute__((__packed__));

template<typename T, typename P>
struct PPP_CP_PAYLOAD {
    T code;
    uint8_t identifier;
    uint16_t length;
    P payload;
}__attribute__((__packed__));

struct Packet {
    ETHERNET_HDR *eth { nullptr };
    PPPOEDISC_HDR *pppoe_discovery { nullptr };
    PPPOESESSION_HDR *pppoe_session { nullptr };
    PPP_CP<LCP_CODE> *lcp { nullptr };
    std::vector<uint8_t> bytes;

    Packet( std::vector<uint8_t> p ):
        bytes( std::move( p ) )
    {}
};

struct LCP {
    std::tuple<Packet,std::string> processReq();
};

#endif