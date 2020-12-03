#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "aaa.hpp"
#include "policy.hpp"

enum class AAA_METHODS: uint8_t {
    NONE,
    LOCAL,
    RADIUS
};

struct FRAMED_POOL {
    address_v4_t start_ip;
    address_v4_t stop_ip;
    std::set<uint32_t> ips;

    FRAMED_POOL() = default;
    
    FRAMED_POOL( uint32_t sta, uint32_t sto ):
        start_ip( sta ),
        stop_ip( sto )
    {}

    FRAMED_POOL( std::string sta, std::string sto );

    uint32_t allocate_ip();
    void deallocate_ip( uint32_t i );
};

struct PPPOELocalTemplate {
    std::string framed_pool;
    address_v4_t dns1;
    address_v4_t dns2;
    std::string vrf;
    std::string unnumbered;
};

struct AAARadConf {
    address_v4_t address;
    uint16_t port;
    std::string secret;

    AAARadConf() = default;

    AAARadConf( const std::string &a, uint16_t p, std::string s ):
        address( address_v4_t::from_string( a ) ),
        port( p ),
        secret( std::move( s ) )
    {}
};

struct AAAConf {
    std::vector<AAA_METHODS> method;
    std::map<std::string,FRAMED_POOL> pools;
    std::string local_template;
    std::vector<std::string> dictionaries;
    std::map<std::string,AAARadConf> auth_servers;
    std::map<std::string,AAARadConf> acct_servers;
};

struct InterfaceUnit {
    std::optional<network_v4_t> address;
    uint16_t vlan;
    bool admin_state { true };
    std::string vrf;
    std::string unnumbered;

    // Not in YAML config
    int32_t sw_if_index{ -1 };
};

struct InterfaceConf {
    std::string device;
    bool admin_state { true };
    std::optional<uint16_t> mtu;
    std::map<uint16_t,InterfaceUnit> units;
};

struct StaticRIBEntry {
    network_v4_t destination;
    address_v4_t nexthop;
    std::optional<std::string> description;
    int32_t rid_in_vpp;
};

struct StaticRIB {
    std::vector<StaticRIBEntry> entries;
};

struct VRFConf {
    std::string name;
    uint32_t table_id;
    StaticRIB rib;
};

struct PPPOEGlobalConf {
    std::string tap_name;
    std::vector<InterfaceConf> interfaces;
    PPPOEPolicy default_pppoe_conf;
    std::map<uint16_t,PPPOEPolicy> pppoe_confs;
    std::map<std::string,PPPOELocalTemplate> pppoe_templates;
    AAAConf aaa_conf;
    StaticRIB global_rib;
    std::vector<VRFConf> vrfs;
};

#endif