#include "main.hpp"

std::tuple<uint32_t,std::string> AAA::startSession( const std::string &user, const std::string &pass ) {
    log( "AAA: starting session user: " + user + " password: " + pass );
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