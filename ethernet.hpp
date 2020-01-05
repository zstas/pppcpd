struct EthernetHeader {
    std::array<uint8_t,6> dst_mac = {};
    std::array<uint8_t,6> src_mac = {};
    uint16_t ethertype = {};

    EthernetHeader() = default;
    EthernetHeader( std::vector<uint8_t> pkt );
    std::string toString() const;
};