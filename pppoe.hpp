enum class PPPOE_CODE: uint8_t {
    PADI = 0x09,
    PADO = 0x07,
    PADR = 0x19,
    PADS = 0x65
};

struct PPPOEDISC_HDR {
    uint32_t type : 4;
    uint32_t version : 4;
    enum PPPOE_CODE code;
    uint16_t session_id;
    uint16_t length;
}__attribute__((__packed__));

namespace pppoe {
    std::string to_string( const PPPOEDISC_HDR *hdr );
}