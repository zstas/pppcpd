#include "main.hpp"

std::string PPPOERuntime::pendeSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie ) {
    pppoe_conn_t key { mac, outer_vlan, inner_vlan, cookie };

    if( auto const &[it, ret ] = pendingSession.emplace( key ); !ret ) {
        return { "Cannot allocate new Pending session" };
    }
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
                    std::forward_as_tuple( encap, i )
            ); !ret ) {
                return { 0, "Cannot allocate session: cannot emplace new PPPOESession" };
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

    sessionSet.erase( it );
    return "";
}