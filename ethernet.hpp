struct ETHERNET_HDR {
    std::array<uint8_t,6> dst_mac;
    std::array<uint8_t,6> src_mac;
    uint16_t ethertype;
}__attribute__((__packed__));;

namespace ether {
    std::string to_string( ETHERNET_HDR *eth );
}