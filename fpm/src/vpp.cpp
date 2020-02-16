#include "main.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON

VPPAPI::VPPAPI() {
    log( "VPPAPI cstr" );
    auto ret = con.connect( "vbng", nullptr, 32, 32 );
    if( ret == VAPI_OK ) {
        log("VPP API: connected");
    } else {
        log( "VPP API: Cannot connect to vpp" );
    }
}

VPPAPI::~VPPAPI() {
    auto ret = con.disconnect();
    if( ret == VAPI_OK ) {
        log("VPP API: disconnected");
    } else {
        log("VPP API: something went wrong, cannot disconnect");
    }
}

bool VPPAPI::add_route( fpm::Message &m ) {
    vapi::Ip_route_add_del route( con, 0 );
    auto &req = route.get_request().get_payload();
    req.is_add = 1;

    if( !m.has_add_route() ) {
        log( "Message doesn't have add_route value" );
        return false;
    }

    auto &add_route = m.add_route();
    if( add_route.nexthops().size() < 1 ) {
        log( "Cannot install routes without ip at this moment" );
    }
    if( add_route.address_family() == qpb::AddressFamily::IPV4 ) {
        req.route.table_id = 0;
        req.route.prefix.address.af = vapi_enum_address_family::ADDRESS_IP4;
        req.is_multipath = 0;
        // Filling up the route info
        auto &prefix = add_route.key().prefix();
        req.route.prefix.address.un.ip4[0] = prefix.bytes()[0];
        req.route.prefix.address.un.ip4[1] = prefix.bytes()[1];
        req.route.prefix.address.un.ip4[2] = prefix.bytes()[2];
        req.route.prefix.address.un.ip4[3] = prefix.bytes()[3];
        req.route.prefix.len = prefix.length();
        log( std::to_string( prefix.length() ) );
        // Filling up the nexthop info
        auto &nexthops = add_route.nexthops();
        req.route.n_paths = nexthops.size();
        uint8_t i = 0;
        for( auto const &nh: nexthops ) {
            auto &nexthop = nh.address().v4();
            req.route.paths[i].nh.address.ip4[0] = ( nexthop.value() & 0xFF000000 ) >> 24;
            req.route.paths[i].nh.address.ip4[1] = ( nexthop.value() & 0x00FF0000 ) >> 16;
            req.route.paths[i].nh.address.ip4[2] = ( nexthop.value() & 0x0000FF00 ) >> 8;
            req.route.paths[i].nh.address.ip4[3] = ( nexthop.value() & 0x000000FF );
            i++;
        }
    } else if( add_route.address_family() == qpb::AddressFamily::IPV6 ) {

    } else {
        return false;
    }

    auto ret = route.execute();
    if( ret != VAPI_OK ) {
        log( "error!" );
    }

    do {
        ret = con.wait_for_response( route );
    } while( ret == VAPI_EAGAIN );

    auto repl = route.get_response().get_payload();
    if( static_cast<int>( repl.stats_index ) == -1 ) {
        log( "cannot add route" );
        return false;
    }
    log( "successfully installed route: " + std::to_string( repl.stats_index ) );
    return true;
}

bool VPPAPI::del_route( fpm::Message &m ) {
    return true;
}