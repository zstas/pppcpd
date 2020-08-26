#ifndef RUNTIME_HPP
#define RUNTIME_HPP

#include <memory>

#include "aaa.hpp"
#include "ethernet.hpp"
#include "encap.hpp"
#include "config.hpp"
#include "vpp.hpp"

class AAA;

class pppoe_conn_t {
    mac_t mac;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
    std::string cookie;
public:
    pppoe_conn_t() = delete;
    pppoe_conn_t( mac_t m, uint16_t o, uint16_t i, std::string c ):
        mac( m ),
        outer_vlan( o ),
        inner_vlan( i ),
        cookie( std::move( c ) )
    {}

    friend bool operator<( const pppoe_conn_t &l, const pppoe_conn_t &r );
    friend std::ostream& operator<<( std::ostream &stream, const pppoe_conn_t &conn ); 

    std::string to_string() const;
};

class pppoe_key_t {
    mac_t mac;
    uint16_t session_id;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
public:
    pppoe_key_t() = delete;
    pppoe_key_t( mac_t m, uint16_t s, uint16_t o, uint16_t i ):
        mac( m ),
        session_id( s ),
        outer_vlan( o ),
        inner_vlan( i )
    {}

    pppoe_key_t( const encapsulation_t &encap, uint16_t s ):
        mac( encap.source_mac ),
        session_id( s ),
        outer_vlan( encap.outer_vlan ),
        inner_vlan( encap.inner_vlan )
    {}

    friend bool operator<( const pppoe_key_t &l, const pppoe_key_t &r );
    friend std::ostream& operator<<( std::ostream &stream, const pppoe_key_t &key ); 

    std::string to_string() const;
};

class PPPOERuntime {
public:
    PPPOERuntime() = delete;
    PPPOERuntime( const PPPOERuntime& ) = delete;
    PPPOERuntime( PPPOERuntime&& ) = default;
    PPPOERuntime( PPPOEGlobalConf newconf, io_service &i );

    PPPOERuntime operator=( const PPPOERuntime& ) = delete;
    PPPOERuntime& operator=( PPPOERuntime&& ) = default;

    PPPOEGlobalConf conf;
    mac_t hwaddr { 0, 0, 0, 0, 0, 0 };
    std::unique_ptr<Logger> logger;
    std::map<pppoe_key_t,PPPOESession> activeSessions;
    std::shared_ptr<LCPPolicy> lcp_conf;
    std::shared_ptr<AAA> aaa;
    std::shared_ptr<VPPAPI> vpp;

    void clearPendingSession( std::shared_ptr<boost::asio::steady_timer> timer, pppoe_conn_t key );
    std::string pendeSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie );
    bool checkSession( mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan, const std::string &cookie );
    std::tuple<uint16_t,std::string> allocateSession( const encapsulation_t &encap );
    std::string deallocateSession( uint16_t sid );

private:
    std::set<uint16_t> sessionSet;
    std::set<pppoe_conn_t> pendingSession;
    io_service &io;
};

#endif