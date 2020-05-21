#include "main.hpp"

void AAA::startSession( const std::string &user, const std::string &pass, aaa_callback callback ) {
    for( auto const &m: method ) {
        switch( m ) {
        case AAA_METHODS::NONE:
            if( auto const &[ sid, err ] = startSessionNone( user, pass ); !err.empty() ) {
                continue;
            } else {
                callback( sid, err );
            }
            break;
        case AAA_METHODS::RADIUS:
            if( auto const &[ sid, err ] = startSessionRadius( user, pass ); !err.empty() ) {
                continue;
            } else {
                callback( sid, err );
            }
            break;
        default:
            break;
        }
    }
}

std::tuple<uint32_t,std::string> AAA::startSessionRadius( const std::string &user, const std::string &pass ) {
    log( "AAA: RADIUS auth, starting session user: " + user + " password: " + pass );

    RadiusRequest req;
    req.username = user;
    req.password = pass;
    req.framed_protocol = "PPP";
    req.nas_id = "vBNG";
    req.service_type = "Framed-User";

    for( auto &[ id, serv ]: auth ) {
        //serv.request( req,  )
    }

    return { 0, "Cannot send any auth requests" };
}

std::tuple<uint32_t,std::string> AAA::startSessionNone( const std::string &user, const std::string &pass ) {
    log( "AAA: NONE auth, starting session user: " + user + " password: " + pass );
    auto address = pool1.allocate_ip();

    // Creating new session
    uint32_t i;
    for( i = 0; i < UINT32_MAX; i++ ) {
        if( auto const &it = sessions.find( i ); it == sessions.end() ) {
            break;
        }
    }
    if( i == UINT32_MAX ) {
        return { i, "No space for new sessions" };
    }

    if( auto const &[ it, ret ] = sessions.try_emplace( i, user, address, pool1 ); !ret ) {
        log( "AAA: failer to emplace user " + user );
        return { SESSION_ERROR, "Failed to emplace user" };
    }
    return { i, "" };
}

std::tuple<AAA_Session,std::string> AAA::getSession( uint32_t sid ) {
    if( auto const &it = sessions.find( sid); it == sessions.end() ) {
        return { AAA_Session{}, "Cannot find session id " + std::to_string( sid ) };
    } else {
        return { it->second, "" };
    }
}

std::string AAA::addRadiusAuth( io_service &io, std::string server_ip, uint16_t port, const std::string secret, const std::string path_to_dict ) {
    uint8_t id = 0;
    for( auto const &[ k, v ]: auth ) {
        id++;
        if( id == k ) {
            continue;
        }
        break;
    }
    RadiusDict dict { path_to_dict };
    auto ip = address_v4::from_string( server_ip );
    if( id != UINT8_MAX ) {
        auth.emplace( std::piecewise_construct, std::forward_as_tuple( id ), std::forward_as_tuple( io, ip, port, secret, dict ) );
    }
    return {};
}

void AAA::changeAuthMethods( std::initializer_list<AAA_METHODS> m ) {
    method = { m };
}