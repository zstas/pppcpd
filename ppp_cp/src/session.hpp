#ifndef SESSION_HPP
#define SESSION_HPP

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

    // PPP FSM for all the protocols we support
    struct LCP_FSM lcp;
    struct PPP_AUTH auth;
    struct IPCP_FSM ipcp;

    // LCP negotiated options
    uint16_t our_MRU;
    uint16_t peer_MRU;
    uint32_t our_magic_number;
    uint32_t peer_magic_number;

    // EVLoop
    io_service &io;
    boost::asio::steady_timer timer;

    PPPOESession( io_service &i, const encapsulation_t &e, uint16_t sid ): 
        io( i ),
        timer( io ),
        encap( e ),
        session_id( sid ),
        lcp( *this ),
        auth( *this ),
        ipcp( *this )
    {
        log( "Session UP: " + std::to_string( sid ) );
    }

    ~PPPOESession() {
        deprovision_dp();
    }

    std::string provision_dp();
    std::string deprovision_dp();
    bool sendEchoReq( const boost::system::error_code& error );
};

#endif