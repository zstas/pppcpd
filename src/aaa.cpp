#include "main.hpp"

bool AAA::startSession( const std::string &user, const std::string &pass ) {
    log( "AAA: starting session user: " + user + " password: " + pass );
    PPP_IPCONF conf;
    conf.address = pool1.allocate_ip();
    conf.dns1 = pool1.dns1;
    conf.dns2 = pool1.dns2;
    if( auto const &[ it, ret ] = confs.emplace( user, conf); !ret ) {
        log( "AAA: failer to emplace user " + user );
        return false;
    }
    return true;
}

std::tuple<PPP_IPCONF,std::string> AAA::getConf( const std::string &user ) {
    if( auto const &it = confs.find( user); it == confs.end() ) {
        return { PPP_IPCONF{}, "Cannot find user " + user };
    } else {
        return { it->second, "" };
    }
}