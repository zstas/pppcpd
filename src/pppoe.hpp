/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

enum class PPPOE_CODE: uint8_t {
    PADI = 0x09,
    PADO = 0x07,
    PADR = 0x19,
    PADS = 0x65,
    PADT = 0xa7
};

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

struct PPPOEDISC_TLV {
    uint16_t type;
    uint16_t length;
    uint8_t *value;
}__attribute__((__packed__));

namespace pppoe {
    std::string to_string( const PPPOEDISC_HDR *hdr );
    uint8_t insertTag( std::vector<uint8_t> &pkt, PPPOE_TAG tag, const std::string &val );
    std::tuple<std::map<PPPOE_TAG,std::string>,std::string> parseTags( std::vector<uint8_t> &pkt );
    std::tuple<std::vector<uint8_t>,std::string> processPPPOE( std::vector<uint8_t> pkt );
}