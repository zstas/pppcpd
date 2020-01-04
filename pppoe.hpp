enum class PPPOE_CODE: uint8_t {
    PADI = 0x09,
    PADO = 0x07,
    PADR = 0x19,
    PADS = 0x65
};

class PPPoE_Discovery {
public:
    uint8_t type_version;
    enum PPPOE_CODE code;
    uint16_t session_id;
    uint16_t length;

    PPPoE_Discovery() = default;
    PPPoE_Discovery( std::vector<uint8_t> pkt );

    std::string toString() const;
};
