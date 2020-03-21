#include "main.hpp"

YAML::Node YAML::convert<global_conf>::encode(const global_conf& rhs) {
    Node node;
    node[ "listen_on_port" ]  = rhs.listen_on_port;
    node[ "my_as" ]           = rhs.my_as;
    node[ "bgp_router_id" ]   = rhs.bgp_router_id.to_string();
    node[ "neighbours" ]      = rhs.neighbours;
    return node;
}

bool YAML::convert<global_conf>::decode(const YAML::Node& node, global_conf& rhs) {
    // if(!node.IsSequence() || node.size() != 3) {
    //     return false;
    // }
    rhs.listen_on_port  = node[ "listen_on_port" ].as<uint16_t>();
    rhs.my_as           = node[ "my_as" ].as<uint32_t>();
    rhs.bgp_router_id   = address_v4::from_string( node["bgp_router_id"].as<std::string>() );
    rhs.neighbours      = node[ "neighbours" ].as<std::list<bgp_neighbour_v4>>();
    return true;
} 

YAML::Node YAML::convert<bgp_neighbour_v4>::encode(const bgp_neighbour_v4& rhs) {
    Node node;
    node["remote_as"]   = rhs.remote_as;
    node["address"]     = rhs.address.to_string();
    return node;
}

bool YAML::convert<bgp_neighbour_v4>::decode(const YAML::Node& node, bgp_neighbour_v4& rhs) {
    rhs.remote_as       = node["remote_as"].as<uint16_t>();
    rhs.address         = address_v4::from_string( node["address"].as<std::string>() );
    return true;
} 
