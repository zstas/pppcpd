#include <memory>
#include <string>
#include <fstream>
#include <yaml-cpp/yaml.h>

#include "runtime.hpp"
#include "log.hpp"
#include "string_helpers.hpp"
#include "yaml.hpp"
#include "aaa.hpp"
#include "ethernet.hpp"
#include "encap.hpp"
#include "vpp_types.hpp"
#include "vpp.hpp"
#include "session.hpp"

PPPOERuntime::PPPOERuntime( std::string cp, io_service &i ) : 
    conf_path( cp ),
    io( i )
{
    logger = std::make_unique<Logger>();
    reloadConfig();
    aaa = std::make_shared<AAA>( io, conf.aaa_conf );

    logger->setLevel( LOGL::INFO );
    logger->logInfo() << LOGS::MAIN << "Starting PPP control plane daemon..." << std::endl;
    vpp = std::make_shared<VPPAPI>( io, logger );
    for( auto const &tapid: vpp->get_tap_interfaces() ) {
        logger->logInfo() << LOGS::MAIN << "Deleting TAP interface with id " << tapid << std::endl;
        auto ret = vpp->delete_tap( tapid );
        if( !ret ) {
            logger->logError() << LOGS::VPP << "Cannot delete tap interface with ifindex: " << tapid << std::endl;
        }
    }
    if( auto const &[ ret, ifi ] = vpp->create_tap( conf.tap_name ); ret ) {
        std::string path { "/proc/sys/net/ipv6/conf/" + conf.tap_name + "/disable_ipv6" };
        std::ofstream dis_ipv6 { path };
        if( dis_ipv6.is_open() ) {
            dis_ipv6 << "1";
            dis_ipv6.close();
        }
        if( !vpp->set_state( ifi, true ) ) {
            logger->logError() << LOGS::VPP << "Cannot set state to interface: " << ifi << std::endl;
        }
        if( !vpp->add_pppoe_cp( ifi ) ) {
            logger->logError() << LOGS::VPP << "Cannot set pppoe cp interface: " << ifi << std::endl;
        }
    }
    for( auto const &vrf: vpp->dump_vrfs() ) {
        if( vrf.table_id == 0 ) {
            // keep default table
            continue;
        }
        logger->logInfo() << LOGS::MAIN << "Deleting VRF " << vrf.name << " with table id: " << vrf.table_id << std::endl;
        if( !vpp->set_vrf( vrf.name, vrf.table_id, false ) ) {
            logger->logError() << LOGS::MAIN << "Cannot delete VRF " << vrf.name << std::endl;
        }
    }
    for( auto const &vrf: conf.vrfs ) {
        if( !vpp->set_vrf( vrf.name, vrf.table_id ) ) {
            logger->logError() << LOGS::MAIN << "Cannot create VRF" << vrf.name << std::endl;
            continue;
        }
        for( auto const &route: vrf.rib.entries ) {
            if( auto const &[ ret, rid ] = vpp->add_route( route.destination, route.nexthop, vrf.table_id ); !ret ) {
                logger->logError() << LOGS::MAIN << "Cannot add route " << route.destination.to_string() << 
                    " via " << route.nexthop.to_string() << " in VRF " << vrf.name << std::endl;
            }
        }
    }
    for( auto const &el: vpp->get_ifaces() ) {
        for( auto const &el: vpp->dump_ip( el.sw_if_index ) ) {
            logger->logInfo() << LOGS::VPP << "Clearing IP on interface " << el.sw_if_index << " addr: " << el.address.to_string() << std::endl;
            vpp->set_ip( el.sw_if_index, el.address, false );
        }
        for( auto const &el: vpp->dump_unnumbered( el.sw_if_index ) ) {
            logger->logInfo() << LOGS::VPP << "Clearing unnumbered on interface " << el.unnumbered_sw_if_index << " IP iface: " << el.iface_sw_if_index << std::endl;
            vpp->set_unnumbered( el.unnumbered_sw_if_index, el.iface_sw_if_index, false );
        }
        if( el.type == IfaceType::SUBIF ) {
            logger->logInfo() << LOGS::VPP << "Deleting subinterface: " << el << std::endl;
            vpp->del_subif( el.sw_if_index );
            continue;
        }
        logger->logInfo() << LOGS::VPP << "Dumped interface: " << el << std::endl;
    }
    vpp->setup_interfaces( conf.interfaces );

    for( auto &rib_entry: conf.global_rib.entries ) {
        if( auto const &[ success, rid ] = vpp->add_route( rib_entry.destination, rib_entry.nexthop, 0 ); success ) {
            rib_entry.rid_in_vpp = rid;
        }
    }
}

void PPPOERuntime::reloadConfig() {
    try {
        YAML::Node config = YAML::LoadFile( conf_path );
        conf = config.as<PPPOEGlobalConf>();
    } catch( std::exception &e ) {
        logger->logError() << LOGS::MAIN << "Error on reloading config: " << e.what() << std::endl;
    }
}

bool operator<( const pppoe_key_t &l, const pppoe_key_t &r ) {
    return std::tie( l.session_id, l.outer_vlan, l.inner_vlan, l.mac ) < std::tie( r.session_id, r.outer_vlan, r.inner_vlan, r.mac );
}

bool operator<( const pppoe_conn_t &l, const pppoe_conn_t &r ) {
    return std::tie( l.cookie, l.outer_vlan, l.inner_vlan, l.mac ) < std::tie( r.cookie, r.outer_vlan, r.inner_vlan, r.mac );
}

std::string PPPOERuntime::pendeSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie ) {
    pppoe_conn_t key { mac, outer_vlan, inner_vlan, cookie };

    if( auto const &[it, ret ] = pendingSession.emplace( key ); !ret ) {
        return { "Cannot allocate new Pending session" };
    }

    auto timer_to_delete = std::make_shared<boost::asio::steady_timer>( io, boost::asio::chrono::seconds( 10 ) );
    timer_to_delete->async_wait( std::bind( &PPPOERuntime::clearPendingSession, this, timer_to_delete, key ) );
    return {};
}

bool PPPOERuntime::checkSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie ) {
    pppoe_conn_t key { mac, outer_vlan, inner_vlan, cookie };

    if( auto const &it = pendingSession.find( key ); it != pendingSession.end() ) {
        pendingSession.erase( it );
        return true;
    }
    return false;
}

std::tuple<uint16_t,std::string> PPPOERuntime::allocateSession( const encapsulation_t &encap ) {
    for( uint16_t i = 1; i < UINT16_MAX; i++ ) {
        if( auto ret = sessionSet.find( i ); ret == sessionSet.end() ) {
            if( auto const &[ it, ret ] = sessionSet.emplace( i ); !ret ) {
                return { 0, "Cannot allocate session: cannot emplace value in set" };
            }
            if( auto const &[ it, ret ] = activeSessions.emplace( std::piecewise_construct,
                    std::forward_as_tuple( encap, i ),
                    std::forward_as_tuple( io, encap, i )
            ); !ret ) {
                return { 0, "Cannot allocate session: cannot emplace new PPPOESession" };
            } else {
                logger->logDebug() << LOGS::MAIN << "Allocated PPPOE Session: " << it->first << std::endl;
            }
            return { i, "" };
        }
    }
    return { 0, "Maximum of sessions" };
}

std::string PPPOERuntime::deallocateSession( uint16_t sid ) {
    auto const &it = sessionSet.find( sid );
    if( it == sessionSet.end() ) {
        return "Cannot find session with this session id";
    }

    for( auto const &[ k, v ]: activeSessions ) {
        if( v.session_id == *it ) {
            aaa->stopSession( v.aaa_session_id );
            logger->logDebug() << LOGS::MAIN << "Dellocated PPPOE Session: " << k << std::endl;
            activeSessions.erase( k );
            break;
        }
    }

    sessionSet.erase( it );
    return "";
}

void PPPOERuntime::clearPendingSession( std::shared_ptr<boost::asio::steady_timer> timer, pppoe_conn_t key ) {
    if( auto const &it = pendingSession.find( key ); it != pendingSession.end() ) {
        logger->logDebug() << LOGS::MAIN << "Deleting pending session due timeout: " << key << std::endl;
        pendingSession.erase( it );
    }
}