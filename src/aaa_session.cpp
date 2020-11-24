#include <iostream>
#include <memory>
#include <functional>

#include "aaa_session.hpp"
#include "radius_dict.hpp"
#include "request_response.hpp"
#include "vpp.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

AAA_Session::AAA_Session( io_service &i, uint32_t sid, const std::string &u, PPPOELocalTemplate &t ):
    io( i ),
    timer( io ),
    session_id( sid ),
    username( u ),
    templ( t ),
    dns1( t.dns1 ),
    dns2( t.dns2 )
{
    auto const &fr_pool = runtime->conf.aaa_conf.pools.find( templ.framed_pool );
    if( fr_pool == runtime->conf.aaa_conf.pools.end() ) {
    }
    address = address_v4_t{ fr_pool->second.allocate_ip() };
    runtime->logger->logDebug() << LOGS::AAA << "Allocated IP: " << address.to_string() << std::endl;
    free_ip = true;
}

AAA_Session::AAA_Session( io_service &i, uint32_t sid, const std::string &u, PPPOELocalTemplate &t, RadiusResponse resp, std::shared_ptr<AuthClient> s ):
    io( i ),
    timer( io ),
    session_id( sid ),
    username( u ),
    templ( t ),
    dns1( resp.dns1 ),
    dns2( resp.dns2 ),
    address( resp.framed_ip ),
    acct( s )
{
    if( address.to_uint() == 0 ) {
        if( !resp.framed_pool.empty() ) {
            auto const &fr_pool = runtime->conf.aaa_conf.pools.find( resp.framed_pool );
            if( fr_pool == runtime->conf.aaa_conf.pools.end() ) {
                address = address_v4_t{ fr_pool->second.allocate_ip() };
            }
        }
    }
}

AAA_Session::~AAA_Session() {
    if( free_ip ) {
        auto const &fr_pool = runtime->conf.aaa_conf.pools.find( templ.framed_pool );
        if( fr_pool == runtime->conf.aaa_conf.pools.end() ) {
            runtime->logger->logDebug() << LOGS::AAA << "Can't deallocate IP: " << address.to_string() << ", can't find the pool" << std::endl;
            return;
        }
        fr_pool->second.deallocate_ip( address.to_uint() );
    }
}

void AAA_Session::start() {
    AcctRequest req;
    req.session_id = "session_" + std::to_string( session_id );
    req.acct_status_type = "Start";
    req.nas_id = "vBNG";
    req.username = username;
    req.in_pkts = 0;
    req.out_pkts = 0;
    req.in_bytes = 0;
    req.out_bytes = 0;

    acct->acct_request( req, 
        std::bind( &AAA_Session::on_started, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ),
        std::bind( &AAA_Session::on_failed, shared_from_this(), std::placeholders::_1 )
    );
}

void AAA_Session::stop() {
    auto const &[ ret, counters ] = runtime->vpp->get_counters_by_index( ifindex );
    AcctRequest req;
    req.session_id = "session_" + std::to_string( session_id );
    req.acct_status_type = "Stop";
    req.nas_id = "vBNG";
    req.username = username;
    if( !ret ) {
        req.in_pkts = 0;
        req.out_pkts = 0;
        req.in_bytes = 0;
        req.out_bytes = 0;
    } else {
        req.in_pkts = counters.rxPkts;
        req.out_pkts = counters.txPkts;
        req.in_bytes = counters.rxBytes;
        req.out_bytes = counters.txBytes;
    }

    acct->acct_request( req, 
        std::bind( &AAA_Session::on_stopped, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ),
        std::bind( &AAA_Session::on_failed, shared_from_this(), std::placeholders::_1 )
    );
}

void AAA_Session::on_started( RADIUS_CODE code, std::vector<uint8_t> pkt ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Radius Accouting session started" << std::endl;
    auto resp = deserialize<AcctResponse>( *runtime->aaa->dict, pkt );
    to_stop_acct = true;
    timer.expires_from_now( std::chrono::seconds( 30 ) );
    timer.async_wait( std::bind( &AAA_Session::on_interim, shared_from_this(), std::placeholders::_1 ) );
}

void AAA_Session::on_interim_answer( RADIUS_CODE code, std::vector<uint8_t> pkt ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Radius Accouting update sent" << std::endl;
    auto resp = deserialize<AcctResponse>( *runtime->aaa->dict, pkt );
    timer.expires_from_now( std::chrono::seconds( 30 ) );
    timer.async_wait( std::bind( &AAA_Session::on_interim, shared_from_this(), std::placeholders::_1 ) );
}

void AAA_Session::on_interim( const boost::system::error_code& ec ) {
    if( ec ) {
        runtime->logger->logError() << "Error on interim timer for AAA session: " << ec.message() << std::endl;
        return;
    }

    auto const &[ ret, counters ] = runtime->vpp->get_counters_by_index( ifindex );
    AcctRequest req;
    req.session_id = "session_" + std::to_string( session_id );
    req.acct_status_type = "Alive";
    req.nas_id = "vBNG";
    req.username = username;
    if( !ret ) {
        req.in_pkts = 0;
        req.out_pkts = 0;
        req.in_bytes = 0;
        req.out_bytes = 0;
    } else {
        req.in_pkts = counters.rxPkts;
        req.out_pkts = counters.txPkts;
        req.in_bytes = counters.rxBytes;
        req.out_bytes = counters.txBytes;
    }

    acct->acct_request( req, 
        std::bind( &AAA_Session::on_interim_answer, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ),
        std::bind( &AAA_Session::on_failed, shared_from_this(), std::placeholders::_1 )
    );
}

void AAA_Session::on_stopped( RADIUS_CODE code, std::vector<uint8_t> pkt ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Radius Accouting session stopped" << std::endl;
    auto resp = deserialize<AcctResponse>( *runtime->aaa->dict, pkt );
}

void AAA_Session::on_failed( std::string err ) {
    runtime->logger->logError() << LOGS::SESSION << "Failed to send accouting request" << std::endl;
    // TODO: err handling
}

void AAA_Session::map_iface( uint32_t ifi ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Mapping session to VPP interface with ifindex: " << ifi << std::endl;
    ifindex = ifi;
}