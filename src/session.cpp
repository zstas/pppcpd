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

PPPOESession::~PPPOESession() {
    deprovision_dp();
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

void PPPOESession::startEcho() {
    timer.expires_from_now( std::chrono::seconds( 10 ) );
    timer.async_wait( std::bind( &PPPOESession::sendEchoReq, shared_from_this(), std::placeholders::_1 ) );
}

void PPPOESession::sendEchoReq( const boost::system::error_code& ec ) {
    if( ec ) {
        runtime->logger->logError() << LOGS::SESSION << "Error on timer for LCP ECHO REQ: " << ec.message() << std::endl;
        return;
    }

    lcp.send_echo_req();

    startEcho();
}