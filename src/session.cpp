#include "session.hpp"
#include "runtime.hpp"
#include "vpp.hpp"

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
    if( auto const &[ ret, ifi ] = runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac, vrf, true ); !ret ) {
        return "Cannot add new session to vpp ";
    } else {
        ifindex = ifi;
    }
    if( !vrf.empty() ) {
        if( !runtime->vpp->set_interface_table( ifindex, vrf ) ) {
            return "Cannot move new session to vrf";
        }
    }
    if( !unnumbered.empty() ) {
        auto [ sw_ifi, success ] = runtime->vpp->get_iface_by_name( unnumbered );
        if( !success ) {
            return "Cannot set unnumbered to new session: can't find interface with such name";
        }
        if( !runtime->vpp->set_unnumbered( ifindex, sw_ifi ) ) {
            return "Cannot set unnumbered to new session";
        }
    }
    return {};
}

std::string PPPOESession::deprovision_dp() {
    for( auto const &el: runtime->vpp->dump_unnumbered( ifindex ) ) {
        runtime->vpp->set_unnumbered( el.unnumbered_sw_if_index, el.iface_sw_if_index, false );
    }
    if( auto const &[ ret, ifi ] = runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac, vrf, false ); !ret ) {
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