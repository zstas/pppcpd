struct bgp_neighbour_v4 {
    uint32_t remote_as;
    address_v4 address;
};

struct global_conf {
    uint16_t listen_on_port;
    uint32_t my_as;
    address_v4 bgp_router_id;

    std::list<bgp_neighbour_v4> neighbours;
};

namespace YAML {
    template<>
    struct convert<bgp_neighbour_v4> {
        static Node encode(const bgp_neighbour_v4& rhs);
        static bool decode(const Node& node, bgp_neighbour_v4& rhs);
    };

    template<>
    struct convert<global_conf> {
        static Node encode(const global_conf& rhs);
        static bool decode(const Node& node, global_conf& rhs);
    };
}
