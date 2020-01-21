#include "main.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON

VPPAPI::VPPAPI() {
    auto ret = con.connect( "vbng", nullptr, 32, 32 );
    if( ret != VAPI_OK ) {
        log( "VPP API: Cannot connect to vpp" );
    } else {
        log("VPP API: connected");
    }
}

VPPAPI::~VPPAPI() {
    con.disconnect();
}

bool VPPAPI::add_pppoe_session( uint32_t ip_address, uint16_t session_id, std::array<uint8_t,6> mac ) {
    vapi::Pppoe_add_del_session pppoe( con );

    auto req = pppoe.get_request().get_payload();

    req.client_ip[0] = ( ip_address && 0xFF );
    req.client_ip[1] = ( ip_address && 0xFF00 ) >> 8;
    req.client_ip[2] = ( ip_address && 0xFF0000 ) >> 16;
    req.client_ip[3] = ( ip_address && 0xFF000000 ) >> 24;
    req.is_ipv6 = 0;

    req.client_mac[0] = mac[0]; req.client_mac[1] = mac[1]; req.client_mac[2] = mac[2]; 
    req.client_mac[3] = mac[3]; req.client_mac[4] = mac[4]; req.client_mac[5] = mac[5]; 

    req.decap_vrf_id = 0;
    req.session_id = session_id;
    req.is_add = 1;
    
    auto ret = pppoe.execute();
    if( ret != VAPI_OK ) {
        log( "error!" );
    }

    do {
        ret = con.wait_for_response( pppoe );
    } while( ret == VAPI_EAGAIN );

    auto repl = pppoe.get_response().get_payload();
    log( "added pppoe session: " + std::to_string( repl.sw_if_index ) );
    if( static_cast<int>( repl.sw_if_index ) == -1 ) {
        return false;
    }

    return true;
}