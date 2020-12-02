#ifndef REQUEST_RESPONSE_HPP
#define REQUEST_RESPONSE_HPP

#include "utils.hpp"

class RadiusDict;

template<typename T>
std::vector<uint8_t> serialize( const RadiusDict &dict, const T &v, const authenticator_t &a, const std::string &secret );

template<typename T>
T deserialize( const RadiusDict &dict, std::vector<uint8_t> &v );

struct RadiusRequest {
    std::string username;
    std::string password;
    std::string nas_id;
    std::string service_type;
    std::string framed_protocol;
    std::string calling_station_id;
    std::string nas_port_id;
};

struct RadiusRequestChap {
    std::string username;
    std::string chap_challenge;
    std::string chap_response;
    std::string nas_id;
    std::string service_type;
    std::string framed_protocol;
    std::string calling_station_id;
    std::string nas_port_id;
};

struct RadiusResponse {
    address_v4_t framed_ip;
    address_v4_t dns1;
    address_v4_t dns2;
    std::string framed_pool;
    std::string pppoe_template;
};

struct AcctRequest {
    std::string session_id;
    std::string username;
    std::string nas_id;
    std::string nas_port_id;
    std::string acct_status_type;
    std::string calling_station_id;
    uint32_t in_pkts;
    uint32_t out_pkts;
    uint32_t in_bytes;
    uint32_t out_bytes;
};

struct AcctResponse {

};

#endif