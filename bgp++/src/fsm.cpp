#include "main.hpp"

bgp_fsm::bgp_fsm( io_context &io, bool adm_dis ):
    state( FSM_STATE::IDLE ),
    admin_disabled( adm_dis ),
    ConnectRetryTimer( io ),
    HoldTimer( io ),
    KeepaliveTimer( io )
{}
