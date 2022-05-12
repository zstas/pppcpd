#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <iostream>
#include <memory>
#include <functional>
#include <string>

#include "aaa_session.hpp"
#include "radius_dict.hpp"
#include "request_response.hpp"
#include "vpp_types.hpp"
#include "vpp.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

uint32_t convertDigit( const std::string &in ) {
    uint32_t ret = std::stoi( in );
    if( in.find( "k" ) != std::string::npos ) {
        ret *= 1024;
    }
    if( in.find( "m" ) != std::string::npos ) {
        ret *= 1024 * 1024;
    }
}

PolicerInfo::PolicerInfo( const std::string &in ) {
    std::vector<std::string> input;
    boost::algorithm::split( input, in, boost::is_any_of( "/ " ) );

    if( input.size() == 4 ) {
        rate_in = convertDigit( input[0] );
        burst_in = convertDigit( input[1] );
        rate_out = convertDigit( input[2] );
        burst_out = convertDigit( input[3] );
    }
}

AAA_Session::AAA_Session( io_service &i, uint32_t sid, const std::string &u, const std::string &template_name ):
    io( i ),
    timer( io ),
    session_id( sid ),
    username( u )
{
    if( auto const &tIt = runtime->conf.pppoe_templates.find( template_name ); tIt != runtime->conf.pppoe_templates.end() ) {
        dns1 = tIt->second.dns1;
        dns2 = tIt->second.dns2;
        framed_pool = tIt->second.framed_pool;
        vrf = tIt->second.vrf;
    }
    auto const &fr_pool = runtime->conf.aaa_conf.pools.find( framed_pool );
    if( fr_pool == runtime->conf.aaa_conf.pools.end() ) {
        return;
    }
    address = address_v4_t{ fr_pool->second.allocate_ip() };
    runtime->logger->logDebug() << LOGS::AAA << "Allocated IP: " << address.to_string() << std::endl;
    free_ip = true;

    runtime->logger->logInfo() << "Creating new AAA session: " << username << " " << address.to_string() << " vrf: " << vrf << std::endl;
}

AAA_Session::AAA_Session( io_service &i, uint32_t sid, const std::string &u, const std::string &template_name, RadiusResponse resp, std::shared_ptr<AuthClient> s ):
    io( i ),
    timer( io ),
    session_id( sid ),
    username( u ),
    address( resp.framed_ip ),
    acct( s )
{
    auto template_to_find = template_name;
    if( !resp.pppoe_template.empty() ) {
        template_to_find = resp.pppoe_template;
    }
    if( auto const &tIt = runtime->conf.pppoe_templates.find( template_to_find ); tIt != runtime->conf.pppoe_templates.end() ) {
        dns1 = tIt->second.dns1;
        dns2 = tIt->second.dns2;
        framed_pool = tIt->second.framed_pool;
        vrf = tIt->second.vrf;
        unnumbered = tIt->second.unnumbered;
    }

    // Filling template with RADIUS information
    if( !resp.framed_pool.empty() ) {
        framed_pool = resp.framed_pool;
    }
    if( resp.dns1.to_uint() != 0 ) {
        dns1 = resp.dns1;
    }
    if( resp.dns2.to_uint() != 0 ) {
        dns2 = resp.dns2;
    }
    if( ( address.to_uint() == 0 ) && ( !framed_pool.empty() ) ) {
        auto const &fr_pool = runtime->conf.aaa_conf.pools.find( framed_pool );
        if( fr_pool != runtime->conf.aaa_conf.pools.end() ) {
            address = address_v4_t{ fr_pool->second.allocate_ip() };
            free_ip = true;
        }
    }

    if( !resp.policer_info.empty() ) {
        policer.emplace( resp.policer_info );
    }

    runtime->logger->logInfo() << "Creating new AAA session: " << username << " " << address.to_string() << " vrf: " << vrf << std::endl;
}

AAA_Session::~AAA_Session() {
    if( free_ip ) {
        auto const &fr_pool = runtime->conf.aaa_conf.pools.find( framed_pool );
        if( fr_pool == runtime->conf.aaa_conf.pools.end() ) {
            runtime->logger->logDebug() << LOGS::AAA << "Can't deallocate IP: " << address.to_string() << ", can't find the pool" << std::endl;
            return;
        }
        fr_pool->second.deallocate_ip( address.to_uint() );
    }
}

void AAA_Session::start() {
    if( !acct ) {
        return;
    }

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
    if( !acct ) {
        return;
    }
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

    timer.cancel();

    acct->acct_request( req, 
        std::bind( &AAA_Session::on_interim_answer, shared_from_this(), std::placeholders::_1, std::placeholders::_2 ),
        std::bind( &AAA_Session::on_failed, shared_from_this(), std::placeholders::_1 )
    );
}

void AAA_Session::on_stopped( RADIUS_CODE code, std::vector<uint8_t> pkt ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Radius Accouting session stopped" << std::endl;
    auto resp = deserialize<AcctResponse>( *runtime->aaa->dict, pkt );
    timer.cancel();
}

void AAA_Session::on_failed( std::string err ) {
    runtime->logger->logError() << LOGS::SESSION << "Failed to send accouting request" << std::endl;
    // TODO: err handling
}

void AAA_Session::map_iface( uint32_t ifi ) {
    runtime->logger->logInfo() << LOGS::SESSION << "Mapping session to VPP interface with ifindex: " << ifi << std::endl;
    ifindex = ifi;
}
