#include <iostream>

#include "vpp.hpp"

extern "C" {
    #include "vpp-api/client/stat_client.h"
}

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_TAPV2_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_POLICER_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON

std::ostream& operator<<( std::ostream &stream, const IfaceType &iface ) {
    switch( iface ) {
    case IfaceType::HW_IFACE: stream << "HW_IFACE"; break;
    case IfaceType::LOOPBACK: stream << "LOOPBACK"; break;
    case IfaceType::TAP: stream << "TAP"; break;
    case IfaceType::SUBIF: stream << "SUBIF"; break;
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

std::ostream& operator<<( std::ostream &stream, const struct VPPIfaceCounters &ctr ) {
    stream << std::dec;
    stream << "Drops:  " << ctr.drops;
    stream << " TxPkts: " << ctr.txPkts;
    stream << " TxBytes: " << ctr.txBytes;
    stream << " RxPkts: " << ctr.rxPkts;
    stream << " RxBytes: " << ctr.rxBytes;
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

    collect_counters();

    for( auto const &[ ifi, ctrs ]: counters ) {
        // logger->logError() << LOGS::VPP << "Interface ifindex: " << ifi << " Counters: " << ctrs << std::endl;
    }

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

std::tuple<bool,uint32_t> VPPAPI::add_pppoe_session( uint32_t ip_address, uint16_t session_id, std::array<uint8_t,6> mac, bool is_add ) {
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
        return { false, 0 };
    }

    return { true, { repl.sw_if_index } };
}

std::tuple<bool,uint32_t> VPPAPI::add_subif( uint32_t iface, uint16_t outer_vlan, uint16_t inner_vlan ) {
    vapi::Create_subif subif{ con };

    auto &req = subif.get_request().get_payload();
    req.sw_if_index = iface;
    req.outer_vlan_id = outer_vlan;
    req.inner_vlan_id = inner_vlan;
    req.sub_id = outer_vlan;
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
    if( repl.retval == -1 ) {
        return { false, 0 };
    }

    return { true, uint32_t{ repl.sw_if_index } };
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

        if( new_iface.device == "Loopback" ) {
            new_iface.type = IfaceType::LOOPBACK;
        } else if( new_iface.device == "dpdk" ) {
            new_iface.type = IfaceType::HW_IFACE;
        }

        if( vip.type == vapi_enum_if_type::IF_API_TYPE_SUB ) {
            new_iface.type = IfaceType::SUBIF;
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

bool VPPAPI::setup_interfaces( const std::vector<InterfaceConf> &ifaces ) {
    auto vpp_ifs { get_ifaces() };
    std::map<VPPInterface,InterfaceConf> conf;

    for( auto const &iface: ifaces ) {
        auto find_lambda = [ &, iface ]( const VPPInterface &vpp_if ) -> bool {
            if( iface.device == vpp_if.name ) {
                return true;
            }
            return false;
        };
        auto if_it = std::find_if( vpp_ifs.begin(), vpp_ifs.end(), find_lambda );                    
        if( if_it == vpp_ifs.end() ) {
            logger->logError() << LOGS::VPP << "Cannot find interface with device: " << iface.device << std::endl;
            continue;
        }
        auto const &vppif = *if_it;
        // Actual configuration process
        set_state( vppif.sw_if_index, iface.admin_state );
        if( iface.mtu.has_value() ) {
            set_mtu( vppif.sw_if_index, iface.mtu.value() );
        }
        auto conf_ifi = vppif.sw_if_index;
        if( iface.conf_as_subif ) {
            bool ret;
            uint32_t ifi;
            std::tie( ret, ifi ) = add_subif( vppif.sw_if_index, *iface.conf_as_subif, 0 );
            if( !ret ) {
                logger->logError() << LOGS::VPP << "Cannot create subinterface: " << iface.device << " vlan: " << *iface.conf_as_subif << std::endl;
            }
            set_state( ifi, true );
            set_mtu( ifi, iface.mtu.value() );
            conf_ifi = ifi;
        }
        if( iface.address ) {
            set_ip( conf_ifi, iface.address.value() );
        }
        if( iface.gateway ) {
            set_gateway( *iface.gateway );
        }
        for( auto const &vlan: iface.vlans ) {
            bool ret;
            uint32_t ifi;
            std::tie( ret, ifi ) = add_subif( vppif.sw_if_index, vlan, 0 );
            if( !ret ) {
                logger->logError() << LOGS::VPP << "Cannot create subinterface: " << iface.device << " vlan: " << vlan << std::endl;
            }
            set_state( ifi, true );
            set_mtu( ifi, iface.mtu.value() );
        }
    }
    return true;
}

bool VPPAPI::set_mtu( uint32_t ifi, uint16_t mtu ) {
    vapi::Sw_interface_set_mtu setmtu{ con };

    auto &req = setmtu.get_request().get_payload();
    req.sw_if_index = ifi;
    req.mtu[ 0 ] = mtu;
    req.mtu[ 1 ] = mtu;
    req.mtu[ 2 ] = mtu;
    req.mtu[ 3 ] = mtu;

    auto ret = setmtu.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_set_mtu api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( setmtu );
    } while( ret == VAPI_EAGAIN );

    auto repl = setmtu.get_response().get_payload();
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}

bool VPPAPI::set_gateway( address_v4_t gw ) {
    vapi::Ip_route_add_del addroute{ con, 0 };

    auto &req = addroute.get_request().get_payload();
    req.is_add = 1;
    req.route.prefix.len = 0;
    req.route.prefix.address.af = vapi_enum_address_family::ADDRESS_IP4;
    for( auto &b: req.route.prefix.address.un.ip4 ) {
        b = 0;
    }
    auto nhop = gw.to_bytes();
    req.route.paths->nh.address.ip4[ 0 ] = nhop[ 3 ];
    req.route.paths->nh.address.ip4[ 1 ] = nhop[ 2 ];
    req.route.paths->nh.address.ip4[ 2 ] = nhop[ 1 ];
    req.route.paths->nh.address.ip4[ 3 ] = nhop[ 0 ];

    auto ret = addroute.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Sw_interface_set_mtu api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( addroute );
    } while( ret == VAPI_EAGAIN );

    auto repl = addroute.get_response().get_payload();
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}

bool VPPAPI::del_subif( uint32_t sw_if_index ) {
    vapi::Delete_subif del_subif{ con };

    auto &req = del_subif.get_request().get_payload();
    req.sw_if_index = sw_if_index;
    
    auto ret = del_subif.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Delete_subif api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( del_subif );
    } while( ret == VAPI_EAGAIN );

    auto repl = del_subif.get_response().get_payload();
    if( repl.retval < 0 ) {
        return false;
    }

    return true;
}

std::vector<VPP_PPPOE_Session> VPPAPI::dump_pppoe_sessions() {
    std::vector<VPP_PPPOE_Session> output;
    vapi::Pppoe_session_dump dump{ con };

    auto &req = dump.get_request().get_payload();
    req.sw_if_index = ~0;
    
    auto ret = dump.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Delete_subif api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( dump );
    } while( ret == VAPI_EAGAIN );

    for( auto const &el: dump.get_result_set() ) {
        auto &vppsess = el.get_payload();
        VPP_PPPOE_Session sess;

        sess.mac[0] = vppsess.client_mac[0]; sess.mac[1] = vppsess.client_mac[1];
        sess.mac[2] = vppsess.client_mac[2]; sess.mac[3] = vppsess.client_mac[3];
        sess.mac[4] = vppsess.client_mac[4]; sess.mac[5] = vppsess.client_mac[5];
        if( vppsess.client_ip.af == vapi_enum_address_family::ADDRESS_IP4 ) {
            std::array<unsigned char,4> buf { vppsess.client_ip.un.ip4[0], vppsess.client_ip.un.ip4[1], vppsess.client_ip.un.ip4[2], vppsess.client_ip.un.ip4[3] };
            sess.address = address_v4_t{ buf };
        }
        sess.encap_if_index = vppsess.encap_if_index;
        sess.session_id = vppsess.session_id;
        sess.sw_if_index = vppsess.sw_if_index;
        output.push_back( std::move( sess ) );
    }

    return output;
}

void VPPAPI::get_stats( uint32_t sw_if_index ) {
    vapi::Want_interface_events get_stats{ con };

    auto &req = get_stats.get_request().get_payload();
    req.enable_disable = 1;
    req.pid = getpid();
    
    auto ret = get_stats.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Collect_detailed_interface_stats api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( get_stats );
    } while( ret == VAPI_EAGAIN );

    auto repl = get_stats.get_response().get_payload();
    if( repl.retval < 0 ) {
        return ;
    }

    return ;
}

bool VPPAPI::add_pppoe_cp( uint32_t sw_if_index, bool to_del ) {
    vapi::Pppoe_add_del_cp set_cp_iface{ con };

    auto &req = set_cp_iface.get_request().get_payload();
    req.is_add = 1;
    req.sw_if_index = sw_if_index;
    
    auto ret = set_cp_iface.execute();
    if( ret != VAPI_OK ) {
        logger->logError() << LOGS::VPP << "Error on executing Pppoe_add_del_cp api method" << std::endl;
    }

    do {
        ret = con.wait_for_response( set_cp_iface );
    } while( ret == VAPI_EAGAIN );

    auto repl = set_cp_iface.get_response().get_payload();
    if( repl.retval != 0 ) {
        return false;
    }

    return true;
}

void VPPAPI::collect_counters() {
    logger->logDebug() << LOGS::VPP << "Trying to get stats" << std::endl;
    auto client = stat_client_get();
    stat_segment_connect_r( STAT_SEGMENT_SOCKET_FILE, client );
    auto ls = stat_segment_ls_r( nullptr, client );
    for( int i = 0; i < stat_segment_vec_len( ls ); i++ ) {
        auto stat = stat_segment_dump_entry_r( ls[ i ], client );
        if( ! ( strcmp( stat->name, "/if/drops" ) == 0 ||
            strcmp( stat->name, "/if/tx" ) == 0 ||
            strcmp( stat->name, "/if/rx" ) == 0 ) ) {
            continue;
        }
        logger->logDebug() << LOGS::VPP << stat->name << std::endl;
        
        switch( stat->type ) {
        case stat_directory_type_t::STAT_DIR_TYPE_NAME_VECTOR:
        {
            auto vec_size = stat_segment_vec_len( stat->name_vector );
            for( int j = 0; j < vec_size; j++ ) {
                // logger->logInfo() << LOGS::VPP << (char*)stat->name_vector[j] << std::endl;
            }
            break;
        }
        case stat_directory_type_t::STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
        {
            auto vec_size = stat_segment_vec_len( stat->simple_counter_vec );
            for( int j = 0; j < vec_size; j++ ) {
                for( int k = 0; k < stat_segment_vec_len( stat->simple_counter_vec[j] ); k++ ) {
                    auto cIt = counters.find( k );
                    if( cIt == counters.end() ) {
                        counters.emplace( std::piecewise_construct, std::forward_as_tuple( k ), std::forward_as_tuple() );
                        cIt = counters.find( k );
                    }
                    if( strcmp( stat->name, "/if/drops" ) == 0 ) {
                        auto &counters = cIt->second;
                        counters.drops = stat->simple_counter_vec[j][k];
                    }
                }
            }
            break;
        }
        case stat_directory_type_t::STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
        {
            auto vec_size = stat_segment_vec_len( stat->combined_counter_vec );
            for( int j = 0; j < vec_size; j++ ) {
                for( int k = 0; k < stat_segment_vec_len( stat->simple_counter_vec[j] ); k++ ) {
                    auto cIt = counters.find( k );
                    if( cIt == counters.end() ) {
                        counters.emplace( std::piecewise_construct, std::forward_as_tuple( k ), std::forward_as_tuple() );
                        cIt = counters.find( k );
                    }
                    auto &counters = cIt->second;
                    if( strcmp( stat->name, "/if/tx" ) == 0 ) {
                        counters.txBytes = stat->combined_counter_vec[j][k].bytes;
                        counters.txPkts = stat->combined_counter_vec[j][k].packets;
                    } else if( strcmp( stat->name, "/if/rx" ) == 0 ) {
                        counters.rxBytes = stat->combined_counter_vec[j][k].bytes;
                        counters.rxPkts = stat->combined_counter_vec[j][k].packets;
                    }
                }
            }
            break;
        }
        }
        stat_segment_data_free( stat );
    }
    stat_segment_vec_free( ls );
    stat_client_free( client );
}

std::tuple<bool,VPPIfaceCounters> VPPAPI::get_counters_by_index( uint32_t ifindex ) {
    auto it = counters.find( ifindex );
    if( it == counters.end() ) {
        return { false, {} };
    }
    return { true, it->second };
}