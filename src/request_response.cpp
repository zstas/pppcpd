#include <string>
#include <vector>
#include <map>
#include <set>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>

using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

#include "request_response.hpp"
#include "net_integer.hpp"
#include "radius_dict.hpp"
#include "radius_avp.hpp"

static std::string password_pap_process( const authenticator_t &auth, const std::string secret, std::string pass ) {
    std::string result;

    auto nlen = pass.length();
    if( nlen % 16 != 0 ) {
        nlen += 16 - pass.length() % 16;
    }

    while( pass.size() != nlen ) {
        pass.push_back( '\0' );
    }

    auto b1 = secret;
    b1.insert( b1.end(), auth.begin(), auth.end() );
    b1 = md5( b1 );

    for( int i = 0; i < nlen / 16; i++ ) {
        std::array<uint8_t,16> c1;
        for( int j = 0; j < 16; j++ ) {
            c1[ j ] = b1[ j ] ^ pass[ 16*i + j ];
        }    
        result.insert( result.end(), c1.begin(), c1.end() );
        b1 = secret;
        b1.insert( b1.end(), c1.begin(), c1.end() );
        b1 = md5( b1 );
    }

    return result;
}

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
std::vector<uint8_t> serialize<RadiusRequestChap>( const RadiusDict &dict, const RadiusRequestChap &req, const authenticator_t &a, const std::string &secret ) {
    std::set<AVP> avp_set { 
        AVP { dict, "User-Name", req.username },
        AVP { dict, "CHAP-Password", req.chap_response },
        AVP { dict, "CHAP-Challenge", req.chap_challenge },
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
        } else if( attr.first == "Framed-Pool" ) {
            res.framed_pool = { avp.value.begin(), avp.value.end() };
        }
    }
    return res;
}

template<>
std::vector<uint8_t> serialize<AcctRequest>( const RadiusDict &dict, const AcctRequest &req, const authenticator_t &a, const std::string &secret ) {
    std::set<AVP> avp_set {
        AVP { dict, "Acct-Session-Id", req.session_id },
        AVP { dict, "User-Name", req.username },
        AVP { dict, "Acct-Input-Packets", BE32( req.in_pkts ) },
        AVP { dict, "Acct-Output-Packets", BE32( req.out_pkts ) },
        AVP { dict, "Acct-Input-Octets", BE32( req.in_bytes ) },
        AVP { dict, "Acct-Output-Octets", BE32( req.out_bytes ) }
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