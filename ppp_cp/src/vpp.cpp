#include "main.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON

VPPAPI::VPPAPI( boost::asio::io_context &i, std::unique_ptr<Logger> &l ):
        io( i ),
        timer( io ),
        logger( l )
{
    auto ret = con.connect( "vbng", nullptr, 32, 32 );
    if( ret == VAPI_OK ) {
        logger->logInfo() << LOGS::VPP << "Connected to VPP API" << std::endl;
    } else {
        logger->logError() << LOGS::VPP << "Cannot connect to VPP API" << std::endl;
    }
    timer.expires_after( std::chrono::seconds( 10 ) );
    timer.async_wait( std::bind( &VPPAPI::process_msgs, this, std::placeholders::_1 ) );
}

void VPPAPI::process_msgs( boost::system::error_code err ) {
    logger->logError() << LOGS::VPP << "Periodic timer to ping VPP API" << std::endl;
    vapi::Control_ping ping { con };

    auto ret = ping.execute(); 
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Control_ping api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( ping );
    } while( ret == VAPI_EAGAIN );

    timer.expires_after( std::chrono::seconds( 10 ) );
    timer.async_wait( std::bind( &VPPAPI::process_msgs, this, std::placeholders::_1 ) );
}

VPPAPI::~VPPAPI() {
    auto ret = con.disconnect();
    if( ret == VAPI_OK ) {
        logger->logInfo() << LOGS::VPP << "Disconnected from VPP API" << std::endl;
    } else {
        logger->logError() << LOGS::VPP << "Something went wrong, cannot disconnect from VPP API" << std::endl;
    }
}

bool VPPAPI::add_pppoe_session( uint32_t ip_address, uint16_t session_id, std::array<uint8_t,6> mac, bool is_add ) {
    vapi::Pppoe_add_del_session pppoe( con );

    auto &req = pppoe.get_request().get_payload();

    req.client_ip.af = vapi_enum_address_family::ADDRESS_IP4;

    req.client_ip.un.ip4[0] = ( ip_address >> 24 ) & 0xFF;
    req.client_ip.un.ip4[1] = ( ip_address >> 16 ) & 0xFF;
    req.client_ip.un.ip4[2] = ( ip_address >> 8 ) & 0xFF;
    req.client_ip.un.ip4[3] = ( ip_address ) & 0xFF;

    req.client_mac[0] = mac[0]; req.client_mac[1] = mac[1]; req.client_mac[2] = mac[2]; 
    req.client_mac[3] = mac[3]; req.client_mac[4] = mac[4]; req.client_mac[5] = mac[5]; 

    req.decap_vrf_id = 0;
    req.session_id = session_id;
    if( is_add ) {
        req.is_add = 1;
    } else {
        req.is_add = 0;
    }
    
    auto ret = pppoe.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing add_pppoe_session api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( pppoe );
    } while( ret == VAPI_EAGAIN );

    auto repl = pppoe.get_response().get_payload();
    logger->logDebug() << LOGS::VPP << "Added pppoe session: " << repl.sw_if_index << std::endl;
    if( static_cast<int>( repl.sw_if_index ) == -1 ) {
        return false;
    }

    return true;
}

bool VPPAPI::add_subif( uint32_t iface, uint16_t outer_vlan, uint16_t inner_vlan ) {
    vapi::Create_subif subif{ con };

    auto &req = subif.get_request().get_payload();
    req.sw_if_index = iface;
    req.outer_vlan_id = outer_vlan;
    req.inner_vlan_id = inner_vlan;
    req.sub_id = 0;
    req.sub_if_flags = vapi_enum_sub_if_flags::SUB_IF_API_FLAG_EXACT_MATCH;
    if( inner_vlan != 0 ) {
        req.sub_if_flags = static_cast<vapi_enum_sub_if_flags>( req.sub_if_flags | vapi_enum_sub_if_flags::SUB_IF_API_FLAG_TWO_TAGS );
    } else {
        req.sub_if_flags = static_cast<vapi_enum_sub_if_flags>( req.sub_if_flags | vapi_enum_sub_if_flags::SUB_IF_API_FLAG_ONE_TAG );
    }

    auto ret = subif.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Create_subif api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( subif );
    } while( ret == VAPI_EAGAIN );

    auto repl = subif.get_response().get_payload();
    logger->logDebug() << LOGS::VPP << "Added subif: " << repl.sw_if_index << std::endl;
    if( static_cast<int>( repl.sw_if_index ) == -1 ) {
        return false;
    }

    return true;
}