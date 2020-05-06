#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

std::string PPPOESession::provision_dp() {
    if( !runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac ) ) {
        return "Cannot add new session to vpp ";
    }
    return "";
}

std::string PPPOESession::deprovision_dp() {
    if( !runtime->vpp->add_pppoe_session( address, session_id, encap.source_mac, false ) ) {
        return "Cannot delete session from vpp ";
    }
    return "";
}