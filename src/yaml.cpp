#include "yaml.hpp"

#include "policy.hpp"
#include "config.hpp"
#include "aaa.hpp"

YAML::Node YAML::convert<PPPOEPolicy>::encode( const PPPOEPolicy &rhs ) {
    Node node;
    node["ac_name"] = rhs.ac_name;
    node["service_name"] = rhs.service_name;
    node["insert_cookie"] = rhs.insert_cookie;
    node["ignore_service_name"] = rhs.ignore_service_name;
    return node;
}

bool YAML::convert<PPPOEPolicy>::decode( const YAML::Node &node, PPPOEPolicy &rhs ) {
    rhs.ac_name = node[ "ac_name" ].as<std::string>();
    rhs.service_name = node[ "service_name" ].as<std::vector<std::string>>();
    rhs.insert_cookie = node[ "insert_cookie"].as<bool>();
    rhs.ignore_service_name = node[ "ignore_service_name" ].as<bool>();
    return true;
}

YAML::Node YAML::convert<FRAMED_POOL>::encode( const FRAMED_POOL &rhs ) {
    Node node;
    node["start_ip"] = rhs.start_ip.to_string();
    node["stop_ip"] = rhs.stop_ip.to_string();
    return node;
}

bool YAML::convert<FRAMED_POOL>::decode( const YAML::Node &node, FRAMED_POOL &rhs ) {
    rhs.start_ip = address_v4_t::from_string( node[ "start_ip" ].as<std::string>() ) ;
    rhs.stop_ip = address_v4_t::from_string( node[ "stop_ip" ].as<std::string>() );
    return true;
}

YAML::Node YAML::convert<AAA_METHODS>::encode( const AAA_METHODS &rhs ) {
    Node node;
    switch( rhs ) {
    case AAA_METHODS::NONE:
        node = "NONE"; break;
    case AAA_METHODS::LOCAL:
        node = "LOCAL"; break;
    case AAA_METHODS::RADIUS:
        node = "RADIUS"; break;
    }
    return node;
}

bool YAML::convert<AAA_METHODS>::decode( const YAML::Node &node, AAA_METHODS &rhs ) {
    auto t = node.as<std::string>();
    if( t == "NONE" ) {
        rhs = AAA_METHODS::NONE;
    } else if( t == "LOCAL" ) {
        rhs = AAA_METHODS::LOCAL;
    } else if( t == "RADIUS" ) {
        rhs = AAA_METHODS::RADIUS;
    } else {
        return false;
    }
    return true;
}

YAML::Node YAML::convert<PPPOELocalTemplate>::encode( const PPPOELocalTemplate &rhs ) {
    Node node;
    node["framed_pool"] = rhs.framed_pool;
    node["dns1"] = rhs.dns1.to_string();
    node["dns2"] = rhs.dns2.to_string();
    if( !rhs.vrf.empty() ) {
        node[ "vrf" ] = rhs.vrf;
    }
    if( !rhs.unnumbered.empty() ) {
        node[ "unnumbered" ] = rhs.unnumbered;
    }
    return node;
}

bool YAML::convert<PPPOELocalTemplate>::decode( const YAML::Node &node, PPPOELocalTemplate &rhs ) {
    rhs.framed_pool = node[ "framed_pool" ].as<std::string>();
    rhs.dns1 = address_v4_t::from_string( node[ "dns1" ].as<std::string>() );
    rhs.dns2 = address_v4_t::from_string( node[ "dns2" ].as<std::string>() );
    if( node[ "vrf" ].IsDefined() ) {
        rhs.vrf = node[ "vrf" ].as<std::string>();
    }
    if( node[ "unnumbered" ].IsDefined() ) {
        rhs.unnumbered = node[ "unnumbered" ].as<std::string>();
    }
    return true;
}

YAML::Node YAML::convert<AAAConf>::encode( const AAAConf &rhs ) {
    Node node;
    node[ "pools" ] = rhs.pools;
    node[ "method" ] = rhs.method;
    if( !rhs.local_template.empty() ) {
        node[ "local_template" ] = rhs.local_template;
    }
    node[ "dictionaries" ] = rhs.dictionaries;
    node[ "auth_servers" ] = rhs.auth_servers;
    node[ "acct_servers" ] = rhs.acct_servers;
    return node;
}

bool YAML::convert<AAAConf>::decode( const YAML::Node &node, AAAConf &rhs ) {
    rhs.pools = node[ "pools" ].as<std::map<std::string,FRAMED_POOL>>();
    rhs.method = node[ "method" ].as<std::vector<AAA_METHODS>>();
    if( node[ "local_template" ].IsDefined() ) {
        rhs.local_template = node[ "local_template" ].as<std::string>();
    }
    rhs.dictionaries = node[ "dictionaries" ].as<std::vector<std::string>>();
    rhs.auth_servers = node[ "auth_servers" ].as<std::map<std::string,AAARadConf>>();
    rhs.acct_servers = node[ "acct_servers" ].as<std::map<std::string,AAARadConf>>();
    return true;
}

YAML::Node YAML::convert<InterfaceUnit>::encode( const InterfaceUnit &rhs ) {
    Node node;
    node[ "admin_state" ] = rhs.admin_state;
    if( rhs.address.has_value() ) {
        node[ "address" ] = rhs.address.value().to_string();
    }
    if( rhs.vlan ) {
        node[ "vlan" ] = *rhs.vlan;
    }
    if( !rhs.vrf.empty() ) {
        node[ "vrf" ] = rhs.vrf;
    }
    return node;
}

bool YAML::convert<InterfaceUnit>::decode( const YAML::Node &node, InterfaceUnit &rhs ) {
    if( node[ "admin_state" ].IsDefined() ) {
        rhs.admin_state = node[ "admin_state" ].as<bool>();
    }
    if( node[ "address" ].IsDefined() ) {
        rhs.address = boost::asio::ip::make_network_v4( node[ "address" ].as<std::string>() );
    }
    if( node[ "vrf" ].IsDefined() ) {
        rhs.vlan = node[ "vlan" ].as<uint16_t>();
    }
    if( node[ "vrf" ].IsDefined() ) {
        rhs.vrf = node[ "vrf" ].as<std::string>();
    }
    return true;
}

YAML::Node YAML::convert<InterfaceConf>::encode( const InterfaceConf &rhs ) {
    Node node;
    node[ "device" ] = rhs.device;
    node[ "admin_state" ] = rhs.admin_state;
    if( rhs.mtu ) {
        node[ "mtu" ] = *rhs.mtu;
    }
    node[ "units" ] = rhs.units;
    return node;
}

bool YAML::convert<InterfaceConf>::decode( const YAML::Node &node, InterfaceConf &rhs ) {
    rhs.device = node[ "device" ].as<std::string>();
    rhs.admin_state = node[ "admin_state" ].as<bool>();
    if( node[ "mtu" ].IsDefined() ) {
        rhs.mtu = node[ "mtu" ].as<uint16_t>();
    }
    rhs.units = node[ "units" ].as<std::map<uint16_t,InterfaceUnit>>();
    return true;
}

YAML::Node YAML::convert<PPPOEGlobalConf>::encode( const PPPOEGlobalConf &rhs ) {
    Node node;
    node[ "tap_name" ] = rhs.tap_name;
    node[ "interfaces" ] = rhs.interfaces;
    node[ "default_pppoe_conf" ] = rhs.default_pppoe_conf;
    node[ "pppoe_confs" ] = rhs.pppoe_confs;
    node[ "pppoe_templates" ] = rhs.pppoe_templates;
    node[ "aaa_conf" ] = rhs.aaa_conf;
    node[ "global_rib" ] = rhs.global_rib;
    node[ "vrfs" ] = rhs.vrfs;
    return node;
}

bool YAML::convert<PPPOEGlobalConf>::decode( const YAML::Node &node, PPPOEGlobalConf &rhs ) {
    rhs.tap_name = node[ "tap_name" ].as<std::string>();
    rhs.interfaces = node[ "interfaces" ].as<std::vector<InterfaceConf>>();
    rhs.default_pppoe_conf = node[ "default_pppoe_conf" ].as<PPPOEPolicy>();
    rhs.pppoe_confs = node[ "pppoe_confs" ].as<std::map<uint16_t,PPPOEPolicy>>();
    rhs.pppoe_templates = node[ "pppoe_templates" ].as<std::map<std::string,PPPOELocalTemplate>>();
    rhs.aaa_conf = node[ "aaa_conf" ].as<AAAConf>();
    rhs.global_rib = node[ "global_rib" ].as<StaticRIB>();
    if( node["vrfs"].IsDefined() ) {
        rhs.vrfs = node[ "vrfs" ].as<std::vector<VRFConf>>();
    }
    return true;
}

YAML::Node YAML::convert<AAARadConf>::encode( const AAARadConf &rhs ) {
    Node node;
    node[ "address" ] = rhs.address.to_string();
    node[ "port" ] = rhs.port;
    node[ "secret" ] = rhs.secret;
    return node;
}

bool YAML::convert<AAARadConf>::decode( const YAML::Node &node, AAARadConf &rhs ) {
    rhs.address = address_v4_t::from_string( node[ "address" ].as<std::string>() );
    rhs.port = node[ "port" ].as<uint16_t>();
    rhs.secret = node[ "secret" ].as<std::string>();
    return true;
}

YAML::Node YAML::convert<StaticRIBEntry>::encode( const StaticRIBEntry &rhs ) {
    Node node;
    node[ "destination" ] = rhs.destination.to_string();
    node[ "nexthop" ] = rhs.nexthop.to_string();
    if( rhs.description.has_value() ) {
        node[ "description" ] = *rhs.description;
    }
    return node;
}

bool YAML::convert<StaticRIBEntry>::decode( const YAML::Node &node, StaticRIBEntry &rhs ) {
    rhs.destination = boost::asio::ip::make_network_v4( node[ "destination" ].as<std::string>() );
    rhs.nexthop = address_v4_t::from_string( node[ "nexthop" ].as<std::string>() );
    if( node[ "description" ].IsDefined() ) {
        rhs.description = node[ "description" ].as<std::string>();
    }
    return true;
}

YAML::Node YAML::convert<StaticRIB>::encode( const StaticRIB &rhs ) {
    Node node;
    node[ "entries" ] = rhs.entries;
    return node;
}

bool YAML::convert<StaticRIB>::decode( const YAML::Node &node, StaticRIB &rhs ) {
    rhs.entries = node[ "entries" ].as<std::vector<StaticRIBEntry>>();
    return true;
}

YAML::Node YAML::convert<VRFConf>::encode( const VRFConf &rhs ) {
    Node node;
    node[ "name" ] = rhs.name;
    node[ "table_id" ] = rhs.table_id;
    node[ "rib" ] = rhs.rib;
    return node;
}

bool YAML::convert<VRFConf>::decode( const YAML::Node &node, VRFConf &rhs ) {
    rhs.name = node[ "name" ].as<std::string>();
    rhs.table_id = node[ "table_id" ].as<uint32_t>();
    rhs.rib = node[ "rib" ].as<StaticRIB>();
    return true;
}
