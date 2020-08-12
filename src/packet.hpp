#ifndef PACKET_HPP_
#define PACKET_HPP_

#include "ethernet.hpp"

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864
#define ETH_VLAN            0x8100

enum class PPPOE_CODE: uint8_t {
    SESSION_DATA = 0x00,
    PADI = 0x09,
    PADO = 0x07,
    PADR = 0x19,
    PADS = 0x65,
    PADT = 0xa7
};

std::ostream& operator<<( std::ostream &stream, const PPPOE_CODE &pkt ); 

enum class PPP_PROTO : uint16_t {
    IPV4 = 0x0021,
    IPV6 = 0x0057,
    IPV6CP = 0x8057,
    LCP = 0xc021,
    PAP = 0xc023,
    CHAP = 0xc223,
    IPCP = 0x8021,
    LQR = 0xc025,
};

std::ostream& operator<<( std::ostream &stream, const PPP_PROTO &pkt ); 

enum class PPPOE_TAG: uint16_t {
    END_OF_LIST = 0x0000,
    SERVICE_NAME = 0x0101,
    AC_NAME = 0x0102,
    HOST_UNIQ = 0x0103,
    AC_COOKIE = 0x0104,
    VENDOR_SPECIFIC = 0x0105,
    RELAY_SESSION_ID = 0x0110,
    SERVICE_NAME_ERROR = 0x0201,
    AC_SYSTEM_ERROR = 0x0202,
    GENERIC_ERROR = 0x0203,
};

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

enum class PAP_CODE: uint8_t {
    AUTHENTICATE_REQ = 1,
    AUTHENTICATE_ACK = 2,
    AUTHENTICATE_NAK = 3
};

enum class CHAP_CODE: uint8_t {
    CHALLENGE = 1,
    RESPONSE = 2,
    SUCCESS = 3,
    FAILURE = 4
};

enum class LCP_OPTIONS: uint8_t {
    VEND_SPEC = 0,
    MRU = 1,
    AUTH_PROTO = 3,
    QUAL_PROTO = 4,
    MAGIC_NUMBER = 5,
    PROTO_FIELD_COMP = 7,
    ADD_AND_CTRL_FIELD_COMP = 8,
};

enum class IPCP_OPTIONS: uint8_t {
    IP_ADDRESS = 3,
    PRIMARY_DNS = 129,
    SECONDARY_DNS = 131,
};

struct PPPOEDISC_TLV {
    uint16_t type;
    uint16_t length;
    uint8_t *value;
}__attribute__((__packed__));

struct PPPOEDISC_HDR {
    uint32_t type : 4;
    uint32_t version : 4;
    enum PPPOE_CODE code;
    uint16_t session_id;
    uint16_t length;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));
static_assert( sizeof( PPPOEDISC_HDR ) == 6 );

struct PPPOESESSION_HDR {
    uint32_t type : 4;
    uint32_t version : 4;
    enum PPPOE_CODE code;
    uint16_t session_id;
    uint16_t length;
    uint16_t ppp_protocol;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));
static_assert( sizeof( PPPOESESSION_HDR ) == 8 );

struct LCP_OPT_HDR {
    LCP_OPTIONS opt;
    uint8_t len;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct IPCP_OPT_HDR {
    IPCP_OPTIONS opt;
    uint8_t len;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct PPP_LCP {
    LCP_CODE code;
    uint8_t identifier;
    uint16_t length;

    uint8_t* getPayload( size_t offset = 0 ) {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this ) + offset;
    }

    std::set<LCP_OPT_HDR*> parseLCPOptions() {
        std::set<LCP_OPT_HDR*> options;
        size_t offset = 0;
        do {
            auto opt = reinterpret_cast<LCP_OPT_HDR*>( getPayload( offset ) );
            offset += opt->len;
        } while( offset + sizeof( *this ) < bswap( length ) );
        return options;
    }

    std::set<IPCP_OPT_HDR*> parseIPCPOptions() {
        std::set<IPCP_OPT_HDR*> options;
        size_t offset = 0;
        while( offset + sizeof( *this ) < bswap( length ) ) {
            auto opt = reinterpret_cast<IPCP_OPT_HDR*>( getPayload( offset ) );
            offset += opt->len;
            options.emplace( opt );
        } 
        return options;
    }
}__attribute__((__packed__));

struct PPP_LCP_ECHO {
    LCP_CODE code;
    uint8_t identifier;
    uint16_t length;
    uint32_t magic_number;
}__attribute__((__packed__));

struct PPP_AUTH_HDR {
    PAP_CODE code;
    uint8_t identifier;
    uint16_t length;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct PPP_CHAP_HDR {
    CHAP_CODE code;
    uint8_t identifier;
    uint16_t length;
    uint8_t value_len;

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct LCP_OPT_1B {
    LCP_OPTIONS opt;
    uint8_t len;
    uint8_t val;

    void set( LCP_OPTIONS o, uint8_t v ) {
        opt = o;
        val = v;
        len = 3;
    }

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct LCP_OPT_2B {
    LCP_OPTIONS opt;
    uint8_t len;
    uint16_t val;

    void set( LCP_OPTIONS o, uint16_t v ) {
        opt = o;
        val = bswap( v );
        len = 4;
    }

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct LCP_OPT_4B {
    LCP_OPTIONS opt;
    uint8_t len;
    uint32_t val;

    void set( LCP_OPTIONS o, uint32_t v ) {
        opt = o;
        val = bswap( v );
        len = 6;
    }

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct IPCP_OPT_4B {
    IPCP_OPTIONS opt;
    uint8_t len;
    uint32_t val;

    void set( IPCP_OPTIONS o, uint32_t v ) {
        opt = o;
        val = bswap( v );
        len = 6;
    }

    uint8_t* getPayload() {
        return reinterpret_cast<uint8_t*>( this ) + sizeof( *this );
    }
}__attribute__((__packed__));

struct Packet {
    ETHERNET_HDR *eth { nullptr };
    VLAN_HDR *vlan { nullptr };
    PPPOEDISC_HDR *pppoe_discovery { nullptr };
    PPPOESESSION_HDR *pppoe_session { nullptr };
    PPP_LCP *lcp { nullptr };
    PPP_AUTH_HDR *auth { nullptr };
    PPP_LCP_ECHO *lcp_echo { nullptr };
    
    std::vector<uint8_t> bytes;

    Packet() = default;

    Packet( std::vector<uint8_t> p ):
        bytes( std::move( p ) )
    {}

    Packet( const Packet & ) = delete;
    Packet& operator=( const Packet& ) = delete;
};

struct PacketPrint {
    std::vector<uint8_t> &bytes;

    PacketPrint( std::vector<uint8_t> &p ):
        bytes( p )
    {}

    friend std::ostream& operator<<( std::ostream &stream, const PacketPrint &pkt ); 
};

#endif