#include "main.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_SESSION_API_JSON

vpp_api::vpp_api() {
    log( "vpp_api cstr" );
    auto ret = con.connect( "bgp++", nullptr, 32, 32 );
    if( ret == VAPI_OK ) {
        log("VPP API: connected");
    } else {
        log( "VPP API: Cannot connect to vpp" );
    }
}

vpp_api::~vpp_api() {
    auto ret = con.disconnect();
    if( ret == VAPI_OK ) {
        log("VPP API: disconnected");
    } else {
        log("VPP API: something went wrong, cannot disconnect");
    }
}

int32_t vpp_api::bind( uint16_t port ) {
    vapi::Bind_sock bound { con };

    auto &req = bound.get_request().get_payload();
    req.vrf = 0;
    for( auto &octet: req.ip ) {
        octet = 0;
    }
    // req.ip[0] = 0;
    // req.ip[1] = 0;
    // req.ip[2] = 0;
    // req.ip[3] = 0;
    req.is_ip4 = 1;
    req.port = port;
    req.proto = 0; // protocol 0 - TCP 1 - UDP

    auto ret = bound.execute();
    if( ret != VAPI_OK ) {
        log( "error!" );
    }

    do {
        ret = con.wait_for_response( bound );
    } while( ret == VAPI_EAGAIN );

    auto repl = bound.get_response().get_payload();
    return repl.retval;
}

bool vpp_api::attach_application() {
    vapi::App_attach attach { con };

    auto &req = attach.get_request().get_payload();
    req.namespace_id[0] = 0;
    req.namespace_id_len = 0;
    req.options[0] = 0;

    auto ret = attach.execute();
    if( ret != VAPI_OK ) {
        log( "error!" );
    }

    do {
        ret = con.wait_for_response( attach );
    } while( ret == VAPI_EAGAIN );

    auto repl = attach.get_response().get_payload();
    return repl.app_index;
}