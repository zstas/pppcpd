#include "main.hpp"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_TAPV2_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON

std::ostream& operator<<( std::ostream &stream, const IfaceType &iface ) {
    switch( iface ) {
    case IfaceType::HW_IFACE: stream << "HW_IFACE"; break;
    case IfaceType::LOOPBACK: stream << "LOOPBACK"; break;
    case IfaceType::TAP: stream << "TAP"; break;
    default: stream << "UNKNOWN"; break;
    }
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const struct VPPInterface &iface ) {
    stream << "VPP interface " << iface.name;
    stream << "; Device: " << iface.device;
    stream << "; mac: " << iface.mac;
    stream << "; ifindex: " << iface.sw_if_index;
    stream << "; speed: " << iface.speed;
    stream << "; MTU: " << iface.mtu;
    stream << "; type: " << iface.type;
    return stream;
}

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

std::tuple<bool,uint32_t> VPPAPI::create_tap( const std::string &host_name ) {
    vapi::Tap_create_v2 tap{ con };

    auto &req = tap.get_request().get_payload();
    strncpy( (char*)req.host_if_name, host_name.c_str(), host_name.length() );
    req.host_if_name_set = true;

    auto ret = tap.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Tap_create_v2 api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( tap );
    } while( ret == VAPI_EAGAIN );

    auto repl = tap.get_response().get_payload();
    logger->logDebug() << LOGS::VPP << "Added tap: " << repl.sw_if_index << std::endl;
    if( repl.retval < 0 ) {
        return { false, 0 };
    }

    return { true, uint32_t{ repl.sw_if_index } };
}

bool VPPAPI::delete_tap( uint32_t id ) {
    vapi::Tap_delete_v2 tap{ con };

    auto &req = tap.get_request().get_payload();
    req.sw_if_index = id;

    auto ret = tap.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Tap_delete_v2 api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( tap );
    } while( ret == VAPI_EAGAIN );

    auto repl = tap.get_response().get_payload();
    logger->logDebug() << LOGS::VPP << "Deleted tap: " << id << std::endl;
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}

std::set<uint32_t> VPPAPI::get_tap_interfaces() {
    std::set<uint32_t> output;
    vapi::Sw_interface_tap_v2_dump dump{ con };

    auto &req = dump.get_request().get_payload();
    req.sw_if_index = ~0;

    auto ret = dump.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_tap_v2_dump api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( dump );
    } while( ret == VAPI_EAGAIN );

    for( auto &el: dump.get_result_set() ) {
        output.emplace( uint32_t{ el.get_payload().sw_if_index } );
    }

    return output;
}

std::vector<VPPInterface> VPPAPI::get_ifaces() {
    std::vector<VPPInterface> output;
    vapi::Sw_interface_dump dump{ con };

    auto &req = dump.get_request().get_payload();

    auto ret = dump.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_dump api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( dump );
    } while( ret == VAPI_EAGAIN );

    for( auto &el: dump.get_result_set() ) {
        auto &vip = el.get_payload();
        VPPInterface new_iface;
        new_iface.speed = vip.link_speed;
        new_iface.mtu = vip.mtu[ 0 ];
        new_iface.sw_if_index = vip.sw_if_index;
        new_iface.device = std::string{ (char*)vip.interface_dev_type, strlen( (char*)vip.interface_dev_type ) };
        new_iface.name = std::string{ (char*)vip.interface_name, strlen( (char*)vip.interface_name ) };
        for( auto i = 0; i < 6; i++ ) {
            new_iface.mac[i] = vip.l2_address[i];
        }

        logger->logDebug() << LOGS::VPP << "Dumped interface: " << new_iface << std::endl;
        output.push_back( std::move( new_iface ) );
    }

    return output;
}

bool VPPAPI::set_ip( uint32_t id, network_v4_t address ) {
    vapi::Sw_interface_add_del_address setaddr{ con };

    auto &req = setaddr.get_request().get_payload();
    req.sw_if_index = id;
    req.is_add = true;
    // req.del_all = true;
    req.prefix.address.af = vapi_enum_address_family::ADDRESS_IP4;
    req.prefix.address.un.ip4[0] = address.address().to_bytes()[0];
    req.prefix.address.un.ip4[1] = address.address().to_bytes()[1];
    req.prefix.address.un.ip4[2] = address.address().to_bytes()[2];
    req.prefix.address.un.ip4[3] = address.address().to_bytes()[3];
    req.prefix.len = address.prefix_length();

    auto ret = setaddr.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_add_del_address api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( setaddr );
    } while( ret == VAPI_EAGAIN );

    auto repl = setaddr.get_response().get_payload();
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}

bool VPPAPI::set_state( uint32_t ifi, bool admin_state ) {
    vapi::Sw_interface_set_flags setstate{ con };

    auto &req = setstate.get_request().get_payload();
    req.sw_if_index = ifi;
    if( admin_state ) {
        req.flags = vapi_enum_if_status_flags::IF_STATUS_API_FLAG_ADMIN_UP;
    } else {
        req.flags = static_cast<vapi_enum_if_status_flags>( 0 );
    }

    auto ret = setstate.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_set_flags api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( setstate );
    } while( ret == VAPI_EAGAIN );

    auto repl = setstate.get_response().get_payload();
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}