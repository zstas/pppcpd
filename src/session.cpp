#include "session.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

PPPOESession::PPPOESession( io_service &i, const encapsulation_t &e, uint16_t sid ): 
    io( i ),
    timer( io ),
    encap( e ),
    session_id( sid ),
    ifindex( UINT32_MAX ),
    lcp( *this ),
    auth( *this ),
    chap( *this ),
    ipcp( *this )
{
    runtime->logger->logDebug() << LOGS::MAIN << "Session UP: " << sid << std::endl;
}

std::string PPPOESession::provision_dp() {
    if( auto const &[ ret, ifi ] = runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac ); !ret ) {
        return "Cannot add new session to vpp ";
    } else {
        ifindex = ifi;
    }
    return {};
}

std::string PPPOESession::deprovision_dp() {
    if( auto const &[ ret, ifi ] = runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac, false ); !ret ) {
        return "Cannot delete session from vpp ";
    }
    return {};
}