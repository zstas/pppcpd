#ifndef CONFIG_HPP
#define CONFIG_HPP

struct InterfaceConf {
    std::string device;
    bool admin_state { true };
    std::optional<uint16_t> mtu;
    std::optional<network_v4_t> address;
    std::vector<uint16_t> vlans;
};

struct PPPOEGlobalConf {
    std::string tap_name;
    std::vector<InterfaceConf> interfaces;
    PPPOEPolicy default_pppoe_conf;
    std::map<uint16_t,PPPOEPolicy> pppoe_confs;
    AAAConf aaa_conf;
};

#endif