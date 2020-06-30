#include "main.hpp"

FRAMED_POOL::FRAMED_POOL( std::string sta, std::string sto ) {
    start_ip = address_v4_t::from_string( sta );
    stop_ip = address_v4_t::from_string( sto );
}

uint32_t FRAMED_POOL::allocate_ip() {
    log( "Allocation IP from Pool" );
    for( uint32_t i = start_ip.to_uint(); i <= stop_ip.to_uint(); i++ ) {
        if( const auto &iIt = ips.find( i ); iIt == ips.end() ) {
            ips.emplace( i );
            return i;
        }
    }
    return 0;
}

void FRAMED_POOL::deallocate_ip( uint32_t i ) {
    log( "Deallocating IP from Pool" );
    if( const auto &iIt = ips.find( i ); iIt != ips.end() ) {
        ips.erase( iIt );
    }
}

void AAA::startSession( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback ) {
    for( auto const &m: conf.method ) {
        switch( m ) {
        case AAA_METHODS::NONE:
            if( auto const &[ sid, err ] = startSessionNone( user, pass ); !err.empty() ) {
                continue;
            } else {
                callback( sid, err );
            }
            break;
        case AAA_METHODS::RADIUS:
            startSessionRadius( user, pass, sess, callback );
            break;
        default:
            break;
        }
    }
}

void AAA::startSessionRadius( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback ) {
    log( "AAA: RADIUS auth, starting session user: " + user + " password: " + pass );

    RadiusRequest req;
    req.username = user;
    req.password = pass;
    req.framed_protocol = "PPP";
    req.nas_id = "vBNG";
    req.service_type = "Framed-User";
    char buf[256];
    snprintf( buf, sizeof( buf ), "%02x:%02x:%02x:%02x:%02x:%02x", 
        sess.encap.destination_mac[ 0 ], 
        sess.encap.destination_mac[ 1 ], 
        sess.encap.destination_mac[ 2 ], 
        sess.encap.destination_mac[ 3 ], 
        sess.encap.destination_mac[ 4 ], 
        sess.encap.destination_mac[ 5 ]
    );
    req.calling_station_id = buf;

    if( sess.encap.outer_vlan == 0 ) {
        req.nas_port_id = "ethernet";
    } else {
        snprintf( buf, sizeof( buf ), "vlan%d", sess.encap.outer_vlan );
        req.nas_port_id = buf;
    }

    for( auto &[ id, serv ]: auth ) {
        serv.request( 
            req, 
            std::bind( &AAA::processRadiusAnswer, this, callback, user, std::placeholders::_1, std::placeholders::_2 ),
            std::bind( &AAA::processRadiusError, this, callback, std::placeholders::_1 )
        );
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

    if( auto const &[ it, ret ] = sessions.try_emplace( i, user, res.framed_ip, res.dns1, res.dns2, nullptr ); !ret ) {
        log( "AAA: failer to emplace user " + user );
        callback( SESSION_ERROR, "Failed to emplace user" );
        return;
    }
    callback( i, "" );
}

void AAA::processRadiusError( aaa_callback callback, const std::string &error ) {
    callback( 0, "RADIUS error: " + error );
}

std::tuple<uint32_t,std::string> AAA::startSessionNone( const std::string &user, const std::string &pass ) {
    log( "AAA: NONE auth, starting session user: " + user + " password: " + pass );
    if( !conf.local_template.has_value() ) {
        return { SESSION_ERROR, "No template for non-radius pppoe user" };
    }
    auto const &fr_pool = conf.pools.find( conf.local_template.value().framed_pool );
    if( fr_pool == conf.pools.end() ) {
        return { SESSION_ERROR, "Framed pool with name " + conf.local_template.value().framed_pool + " wasn't found" };
    }
    address_v4 address { fr_pool->second.allocate_ip() };
    log( "AAA: Allocated ip " + address.to_string() );

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

    if( auto const &[ it, ret ] = sessions.try_emplace( i, user, address, conf.local_template.value().dns1, conf.local_template.value().dns2, on_stop ); !ret ) {
        log( "AAA: failer to emplace user " + user );
        return { SESSION_ERROR, "Failed to emplace user" };
    }
    return { i, "" };
}

std::tuple<AAA_Session*,std::string> AAA::getSession( uint32_t sid ) {
    if( auto const &it = sessions.find( sid); it == sessions.end() ) {
        return { nullptr, "Cannot find session id " + std::to_string( sid ) };
    } else {
        return { &it->second, "" };
    }
}

std::string AAA::addRadiusAuth( io_service &io, std::string server_ip, uint16_t port, const std::string secret, const std::vector<std::string> paths_to_dict ) {
    uint8_t id = 0;
    for( auto const &[ k, v ]: auth ) {
        id++;
        if( id == k ) {
            continue;
        }
        break;
    }
    RadiusDict dict { paths_to_dict };
    auto ip = address_v4::from_string( server_ip );
    if( id != UINT8_MAX ) {
        auth.emplace( std::piecewise_construct, std::forward_as_tuple( id ), std::forward_as_tuple( io, ip, port, secret, dict ) );
    }
    return {};
}

void AAA::stopSession( uint32_t sid ) {
    if( auto const &it = sessions.find( sid ); it != sessions.end() ) {
        sessions.erase( it );
    }
}