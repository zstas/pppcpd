#include "main.hpp"

PPPOERuntime::PPPOERuntime( std::string name, io_service &i ) : 
    ifName( std::move( name ) ),
    io( i )
{
    logger = std::make_unique<Logger>();
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
    if( auto const &[ ret, ifi ] = vpp->create_tap( ifName ); ret ) {
        if( !vpp->set_state( ifi, true ) ) {
            logger->logError() << LOGS::VPP << "Cannot set state to interface: " << ifi << std::endl;
        }
    }
    auto temp = vpp->get_ifaces();
    for( auto const &el: temp ) {
        logger->logInfo() << LOGS::VPP << "Dumped interface: " << el << std::endl;
    }
}

bool operator<( const pppoe_key_t &l, const pppoe_key_t &r ) {
    return std::tie( l.session_id, l.outer_vlan, l.inner_vlan, l.mac ) < std::tie( r.session_id, r.outer_vlan, r.inner_vlan, r.mac );
}

bool operator<( const pppoe_conn_t &l, const pppoe_conn_t &r ) {
    return std::tie( l.cookie, l.outer_vlan, l.inner_vlan, l.mac ) < std::tie( r.cookie, r.outer_vlan, r.inner_vlan, r.mac );
}

std::ostream& operator<<( std::ostream &stream, const pppoe_key_t &key ) {
    stream << "PPPoE Key: mac: " << key.mac << " session id: " << key.session_id << " outer vlan: " << key.outer_vlan << " inner vlan: " << key.inner_vlan;
    return stream;
}

std::ostream& operator<<( std::ostream &stream, const pppoe_conn_t &conn ) {
    stream << "PPPoE Connection: mac: " << conn.mac << " cookie: " << conn.cookie << " outer vlan: " << conn.outer_vlan << " inner vlan: " << conn.inner_vlan;
    return stream;
}

std::string pppoe_conn_t::to_string() const {
    std::ostringstream out;

    out << "MAC: ";
    for( auto const &el: mac ) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out << " outer_vlan: " << outer_vlan;
    out << " inner_vlan: " << inner_vlan;
    out << " cookie: " << cookie;

    return out.str();
}

std::string pppoe_key_t::to_string() const {
    std::ostringstream out;

    out << "MAC: ";
    for( auto const &el: mac ) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out << " session_id: " << session_id;
    out << " outer_vlan: " << outer_vlan;
    out << " inner_vlan: " << inner_vlan;

    return out.str();
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
                logger->logDebug() << LOGS::MAIN << "Allocated PPPOE Session: " << it->first.to_string();
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
            logger->logDebug() << LOGS::MAIN << "Dellocated PPPOE Session: " << k.to_string();
            activeSessions.erase( k );
            break;
        }
    }

    sessionSet.erase( it );
    return "";
}

void PPPOERuntime::clearPendingSession( std::shared_ptr<boost::asio::steady_timer> timer, pppoe_conn_t key ) {
    if( auto const &it = pendingSession.find( key ); it != pendingSession.end() ) {
        logger->logDebug() << LOGS::MAIN << "Deleting pending session due timeout: " << key.to_string();
        pendingSession.erase( it );
    }
}