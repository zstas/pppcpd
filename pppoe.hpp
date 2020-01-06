enum class PPPOE_CODE: uint8_t {
    PADI = 0x09,
    PADO = 0x07,
    PADR = 0x19,
    PADS = 0x65
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
}__attribute__((__packed__));

struct PPPOEDISC_TLV {
    uint16_t type;
    uint8_t length;
    uint8_t *value;
}__attribute__((__packed__));

namespace pppoe {
    std::string to_string( const PPPOEDISC_HDR *hdr );
}