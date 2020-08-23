#include "main.hpp"

template<>
std::vector<uint8_t> serialize<RadiusRequest>( const RadiusDict &dict, const RadiusRequest &req, const authenticator_t &a, const std::string &secret ) {
    std::set<AVP> avp_set { 
        AVP { dict, "User-Name", req.username },
        AVP { dict, "User-Password", password_pap_process( a, secret, req.password ) }
    };

    if( !req.nas_id.empty() ) {
        avp_set.emplace( dict, "NAS-Identifier", req.nas_id );
    }

    if( !req.framed_protocol.empty() ) {
        if( uint32_t val = dict.getValueByName( "Framed-Protocol", req.framed_protocol ); val != 0 ) {
            avp_set.emplace( dict, "Framed-Protocol", BE32{ val } );
        }
    }

    if( !req.service_type.empty() ) {
        if( uint32_t val = dict.getValueByName( "Service-Type", req.service_type ); val != 0 ) {
            avp_set.emplace( dict, "Service-Type", BE32{ val } );
        }
    }

    if( !req.calling_station_id.empty() ) {
        avp_set.emplace( dict, "Calling-Station-Id", req.calling_station_id );
    }

    if( !req.nas_port_id.empty() ) {
        avp_set.emplace( dict, "NAS-Port-Id", req.nas_port_id );
    }

    return serializeAVP( avp_set );
}

template<>
RadiusResponse deserialize<RadiusResponse>( const RadiusDict &dict, std::vector<uint8_t> &v ) {
    RadiusResponse res;

    auto avp_set = parseAVP( v );
    for( auto const &avp: avp_set ) {
        auto const &attr = dict.getAttrById( avp.type, avp.vendor ); 
        if( attr.first == "Framed-IP-Address" ) {
            if( auto const &[ ip, success ] = avp.getVal<BE32>(); success ) {
                res.framed_ip = address_v4_t{ ip.native() };
            } 
        } else if( attr.first == "Client-DNS-Pri" ) {
            if( auto const &[ ip, success ] = avp.getVal<BE32>(); success ) {
                res.dns1 = address_v4_t{ ip.native() };
            } 
        } else if( attr.first == "Client-DNS-Sec" ) {
            if( auto const &[ ip, success ] = avp.getVal<BE32>(); success ) {
                res.dns2 = address_v4_t{ ip.native() };
            } 
        }
    }
    return res;
}

template<>
std::vector<uint8_t> serialize<AcctRequest>( const RadiusDict &dict, const AcctRequest &req, const authenticator_t &a, const std::string &secret ) {
    std::set<AVP> avp_set { 
        AVP { dict, "User-Name", req.username },
        AVP { dict, "Acct-Input-Packets", BE32( req.in_pkts ) },
        AVP { dict, "Acct-Output-Packets", BE32( req.out_pkts ) }
    };

    if( !req.acct_status_type.empty() ) {
        avp_set.emplace( dict, "Acct-Status-Type", req.acct_status_type );
    }

    if( !req.nas_id.empty() ) {
        avp_set.emplace( dict, "NAS-Identifier", req.nas_id );
    }

    if( !req.calling_station_id.empty() ) {
        avp_set.emplace( dict, "Calling-Station-Id", req.calling_station_id );
    }

    if( !req.nas_port_id.empty() ) {
        avp_set.emplace( dict, "NAS-Port-Id", req.nas_port_id );
    }

    return serializeAVP( avp_set );
}

template<>
AcctResponse deserialize<AcctResponse>( const RadiusDict &dict, std::vector<uint8_t> &v ) {
    AcctResponse res;

    auto avp_set = parseAVP( v );
    for( auto const &avp: avp_set ) {
        auto const &attr = dict.getAttrById( avp.type, avp.vendor ); 
        // if( attr.first == "Framed-IP-Address" ) {
        //     if( auto const &[ ip, success ] = avp.getVal<BE32>(); success ) {
        //         res.framed_ip = address_v4_t{ ip.native() };
        //     } 
        // } 
    }
    return res;
}