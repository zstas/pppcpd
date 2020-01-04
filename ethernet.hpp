struct EthernetHeader {
    uint8_t dst_mac[ 6 ];
    uint8_t src_mac[ 6 ];
    uint16_t ethertype;

    EthernetHeader( std::vector<uint8_t> pkt );
    std::string toString() const;
};