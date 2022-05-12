#ifndef SESSION_HPP
#define SESSION_HPP

#include <memory>
#include <optional>

#include "evloop.hpp"
#include "ppp_fsm.hpp"
#include "ppp_auth.hpp"
#include "ppp_ipcp.hpp"
#include "ppp_lcp.hpp"
#include "ppp_chap.hpp"
#include "encap.hpp"
#include "policer_info.hpp"

struct PPPOESession : public std::enable_shared_from_this<PPPOESession> {
    // General Data
    encapsulation_t encap;
    bool started { false };
    uint32_t aaa_session_id{ UINT32_MAX };

    // PPPoE Data
    uint16_t session_id;
    std::string cookie;
    
    // Various data
    std::string username;
    uint32_t address;
    uint32_t ifindex;
    std::string vrf;
    std::string unnumbered;
    std::optional<PolicerInfo> policer_info;

    // PPP FSM for all the protocols we support
    struct LCP_FSM lcp;
    struct PPP_AUTH auth;
    struct PPP_CHAP chap;
    struct IPCP_FSM ipcp;

    // LCP negotiated options
    uint16_t our_MRU;
    uint16_t peer_MRU;
    uint32_t our_magic_number;
    uint32_t peer_magic_number;

    // EVLoop
    io_service &io;
    boost::asio::steady_timer timer;

    PPPOESession( io_service &i, const encapsulation_t &e, uint16_t sid );
    ~PPPOESession();

    std::string provision_dp();
    std::string deprovision_dp();
    void startEcho();
    void sendEchoReq( const boost::system::error_code &ec );
};

#endif
