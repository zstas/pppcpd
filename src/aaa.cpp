#include <iostream>
#include <memory>
#include <functional>

#include "aaa.hpp"
#include "radius_dict.hpp"
#include "request_response.hpp"
#include "vpp.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

AAA_Session::AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, std::function<void()> s ):
    username( u ),
    address( a ),
    dns1( d1 ),
    on_stop( s )
{}

AAA_Session::AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, address_v4_t d2, std::function<void()> s ):
    username( u ),
    address( a ),
    dns1( d1 ),
    dns2( d2 ),
    on_stop( s )
{}

AAA_Session::~AAA_Session() {
    if( on_stop != nullptr ) {
        on_stop();
    }
}

FRAMED_POOL::FRAMED_POOL( std::string sta, std::string sto ) {
    start_ip = address_v4_t::from_string( sta );
    stop_ip = address_v4_t::from_string( sto );
}

uint32_t FRAMED_POOL::allocate_ip() {
    runtime->logger->logDebug() << LOGS::AAA << "Allocation IP from Pool" << std::endl;
    for( uint32_t i = start_ip.to_uint(); i <= stop_ip.to_uint(); i++ ) {
        if( const auto &iIt = ips.find( i ); iIt == ips.end() ) {
            ips.emplace( i );
            return i;
        }
    }
    return 0;
}

void FRAMED_POOL::deallocate_ip( uint32_t i ) {
    runtime->logger->logDebug() << LOGS::AAA << "Deallocating IP from Pool" << std::endl;
    if( const auto &iIt = ips.find( i ); iIt != ips.end() ) {
        ips.erase( iIt );
    }
}

AAA::AAA( io_service &i, AAAConf &c ):
    io( i ),
    conf( c )
{
    if( !conf.dictionaries.empty() ) {
        dict.emplace( conf.dictionaries );
    }

    if( !dict.has_value() ) {
        runtime->logger->logInfo() << LOGS::AAA << "No RADIUS dictionaries provided. RADIUS won't be working." << std::endl;
    }

    for( auto const &[ k, v ]: conf.auth_servers ) {
        auth.emplace( std::piecewise_construct, 
            std::forward_as_tuple( k ),
            std::forward_as_tuple( io, v.address, v.port, v.secret, *dict ) );
    }

    for( auto const &[ k, v ]: conf.acct_servers ) {
        acct.emplace( std::piecewise_construct, 
            std::forward_as_tuple( k ),
            std::forward_as_tuple( io, v.address, v.port, v.secret, *dict ) );
    }
}

void AAA::startSession( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback ) {
    for( auto const &m: conf.method ) {
        switch( m ) {
        case AAA_METHODS::NONE:
            if( auto const &[ sid, err ] = startSessionNone( user, pass ); !err.empty() ) {
                runtime->logger->logError() << LOGS::AAA << "Error when starting new session: " << err << std::endl;
                continue;
            } else {
                callback( sid, err );
            }
            break;
        case AAA_METHODS::RADIUS:
            startSessionRadius( user, pass, sess, std::move( callback ) );
            return;
            break;
        default:
            break;
        }
    }
}

void AAA::startSessionCHAP( const std::string &user, const std::string &challenge, const std::string &response, PPPOESession &sess, aaa_callback callback ) {
    for( auto const &m: conf.method ) {
        switch( m ) {
        case AAA_METHODS::NONE:
            if( auto const &[ sid, err ] = startSessionNone( user, "CHAP" ); !err.empty() ) {
                runtime->logger->logError() << LOGS::AAA << "Error when starting new session: " << err << std::endl;
                continue;
            } else {
                callback( sid, err );
            }
            break;
        case AAA_METHODS::RADIUS:
            startSessionRadiusChap( user, challenge, response, sess, std::move( callback ) );
            return;
            break;
        default:
            break;
        }
    }
}

void AAA::startSessionRadius( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback ) {
    runtime->logger->logDebug() << LOGS::AAA << "RADIUS auth, starting session user: " << user << " password: " << pass << std::endl;

    RadiusRequest req;
    req.username = user;
    req.password = pass;
    req.framed_protocol = "PPP";
    req.nas_id = "vBNG";
    req.service_type = "Framed-User";

    std::ostringstream str;
    str << sess.encap.destination_mac;
    req.calling_station_id = str.str();
    str.str( std::string() );

    if( sess.encap.outer_vlan == 0 ) {
        req.nas_port_id = "ethernet";
    } else {
        str << "vlan" << sess.encap.outer_vlan;
        req.nas_port_id = str.str();
    }

    for( auto &[ id, serv ]: auth ) {
        serv.request( 
            req, 
            std::bind( &AAA::processRadiusAnswer, this, callback, user, std::placeholders::_1, std::placeholders::_2 ),
            std::bind( &AAA::processRadiusError, this, callback, std::placeholders::_1 )
        );
        break;
    }
}

void AAA::startSessionRadiusChap( const std::string &user, const std::string &challenge, const std::string &response, PPPOESession &sess, aaa_callback callback ) {
    runtime->logger->logDebug() << LOGS::AAA << "RADIUS CHAP auth, starting session user: " << user << std::endl;

    RadiusRequestChap req;
    req.username = user;
    req.chap_challenge = challenge;
    req.chap_response = response;
    req.framed_protocol = "PPP";
    req.nas_id = "vBNG";
    req.service_type = "Framed-User";

    std::ostringstream str;
    str << sess.encap.destination_mac;
    req.calling_station_id = str.str();
    str.str( std::string() );

    if( sess.encap.outer_vlan == 0 ) {
        req.nas_port_id = "ethernet";
    } else {
        str << "vlan" << sess.encap.outer_vlan;
        req.nas_port_id = str.str();
    }

    for( auto &[ id, serv ]: auth ) {
        serv.request( 
            req, 
            std::bind( &AAA::processRadiusAnswer, this, callback, user, std::placeholders::_1, std::placeholders::_2 ),
            std::bind( &AAA::processRadiusError, this, callback, std::placeholders::_1 )
        );
        break;
    }
}

void AAA::processRadiusAnswer( aaa_callback callback, std::string user, RADIUS_CODE code, std::vector<uint8_t> v ) {
    auto res = deserialize<RadiusResponse>( *dict, v );

    if( code != RADIUS_CODE::ACCESS_ACCEPT ) {
        callback( 0, "RADIUS answered with no accept" );
    }

    // Creating new session
    uint32_t i;
    for( i = 0; i < UINT32_MAX; i++ ) {
        if( auto const &it = sessions.find( i ); it == sessions.end() ) {
            break;
        }
    }
    if( i == UINT32_MAX ) {
        callback( 0, "No space for new sessions" );
        return;
    }

    if( auto const &[ it, ret ] = sessions.emplace( 
        std::piecewise_construct, 
        std::forward_as_tuple( i ), 
        std::forward_as_tuple( std::make_shared<AAA_Session>( user, res.framed_ip, res.dns1, res.dns2, nullptr ) )
    ); !ret ) {
        runtime->logger->logError() << LOGS::AAA << "failed to emplace user " << user << std::endl;
        callback( SESSION_ERROR, "Failed to emplace user" );
        return;
    }
    callback( i, "" );
}

void AAA::processRadiusError( aaa_callback callback, const std::string &error ) {
    callback( 0, "RADIUS error: " + error );
}

std::tuple<uint32_t,std::string> AAA::startSessionNone( const std::string &user, const std::string &pass ) {
    runtime->logger->logDebug() << LOGS::AAA << "NONE auth, starting session user: " << user << " password: " << pass << std::endl;
    if( !conf.local_template.has_value() ) {
        return { SESSION_ERROR, "No template for non-radius pppoe user" };
    }
    auto const &fr_pool = conf.pools.find( conf.local_template.value().framed_pool );
    if( fr_pool == conf.pools.end() ) {
        return { SESSION_ERROR, "Framed pool with name " + conf.local_template.value().framed_pool + " wasn't found" };
    }
    address_v4_t address { fr_pool->second.allocate_ip() };
    runtime->logger->logDebug() << LOGS::AAA << "Allocated ip " << address.to_string() << std::endl;

    // Creating new session
    uint32_t i;
    for( i = 0; i < UINT32_MAX; i++ ) {
        if( auto const &it = sessions.find( i ); it == sessions.end() ) {
            break;
        }
    }
    if( i == UINT32_MAX ) {
        return { SESSION_ERROR, "No space for new sessions" };
    }

    auto on_stop = std::bind( &FRAMED_POOL::deallocate_ip, &fr_pool->second, address.to_uint() );

    if( auto const &[ it, ret ] = sessions.emplace( 
        std::piecewise_construct,
        std::forward_as_tuple( i ), 
        std::forward_as_tuple( std::make_shared<AAA_Session>( user, address, conf.local_template.value().dns1, conf.local_template.value().dns2, on_stop ) ) 
    ); !ret ) {
        runtime->logger->logError() << LOGS::AAA <<  "failer to emplace user " << user << std::endl;
        return { SESSION_ERROR, "Failed to emplace user" };
    }
    return { i, "" };
}

std::tuple<std::shared_ptr<AAA_Session>,std::string> AAA::getSession( uint32_t sid ) {
    if( auto const &it = sessions.find( sid); it == sessions.end() ) {
        return { nullptr, "Cannot find session id " + std::to_string( sid ) };
    } else {
        return { it->second, "" };
    }
}

void AAA::stopSession( uint32_t sid ) {
    if( auto const &it = sessions.find( sid ); it != sessions.end() ) {
        sessions.erase( it );
    }
}