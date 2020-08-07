#include "main.hpp"

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
    return node;
}

bool YAML::convert<PPPOELocalTemplate>::decode( const YAML::Node &node, PPPOELocalTemplate &rhs ) {
    rhs.framed_pool = node[ "framed_pool" ].as<std::string>();
    rhs.dns1 = address_v4_t::from_string( node[ "dns1" ].as<std::string>() );
    rhs.dns2 = address_v4_t::from_string( node[ "dns2" ].as<std::string>() );
    return true;
}

YAML::Node YAML::convert<AAAConf>::encode( const AAAConf &rhs ) {
    Node node;
    node[ "pools" ] = rhs.pools;
    node[ "method" ] = rhs.method;
    if( rhs.local_template.has_value() ) {
        node[ "local_template" ] = rhs.local_template.value();
    }
    return node;
}

bool YAML::convert<AAAConf>::decode( const YAML::Node &node, AAAConf &rhs ) {
    rhs.pools = node[ "pools" ].as<std::map<std::string,FRAMED_POOL>>();
    rhs.method = node[ "method" ].as<std::vector<AAA_METHODS>>();
    if( node[ "local_template" ].IsDefined() ) {
        rhs.local_template = node[ "local_template" ].as<PPPOELocalTemplate>();
    }
    return true;
}

YAML::Node YAML::convert<InterfaceConf>::encode( const InterfaceConf &rhs ) {
    Node node;
    node[ "device" ] = rhs.device;
    node[ "mtu" ] = rhs.mtu;
    if( rhs.address.has_value() ) {
        node[ "address" ] = rhs.address.value().to_string();
    }
    node[ "vlans" ] = rhs.vlans;
    return node;
}

bool YAML::convert<InterfaceConf>::decode( const YAML::Node &node, InterfaceConf &rhs ) {
    rhs.device = node[ "device" ].as<std::string>();
    rhs.mtu = node[ "mtu" ].as<uint16_t>();
    if( node[ "address" ].IsDefined() ) {
        rhs.address = boost::asio::ip::make_network_v4( node[ "address" ].as<std::string>() );
    }
    rhs.vlans = node[ "vlans" ].as<std::vector<uint16_t>>();
    return true;
}