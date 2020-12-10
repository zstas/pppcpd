#ifndef VPP_TYPES_HPP
#define VPP_TYPES_HPP

#include <iosfwd>

using mac_t = std::array<uint8_t,6>;

enum class IfaceType: uint8_t {
    LOOPBACK,
    HW_IFACE,
    TAP,
    SUBIF
};

struct VPPInterface {
    std::string name;
    std::string device;
    mac_t mac;
    uint32_t sw_if_index;
    uint32_t speed;
    uint16_t mtu;
    IfaceType type;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & name;
        archive & device;
        archive & mac;
        archive & sw_if_index;
        archive & speed;
        archive & mtu;
        archive & type;
    }
};

struct VPP_PPPOE_Session {
    uint16_t session_id;
    mac_t mac;
    address_v4_t address;
    uint32_t sw_if_index;
    uint32_t encap_if_index;
};

struct VPPIfaceCounters {
    uint64_t rxPkts;
    uint64_t rxBytes;
    uint64_t txPkts;
    uint64_t txBytes;
    uint64_t drops;
};

struct VPPVRF {
    std::string name;
    uint32_t table_id;
};

struct VPPIP {
    uint32_t sw_if_index;
    network_v4_t address;
};

struct VPPUnnumbered {
    uint32_t unnumbered_sw_if_index;
    uint32_t iface_sw_if_index;
};

std::ostream& operator<<( std::ostream &stream, const IfaceType &iface );
std::ostream& operator<<( std::ostream &stream, const struct VPPInterface &iface );


#endif