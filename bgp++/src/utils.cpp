#include "main.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

std::ostream& operator<<( std::ostream & os, const LOG_APP & app ) {
    switch( app ) {
    case LOG_APP::APPLICATION:
        os << "[APPLICATION]: ";
        break;
    case LOG_APP::FSM:
        os << "[FSM]: ";
        break;
    case LOG_APP::CONNECTION:
        os << "[CONNECTION]: ";
        break;
    case LOG_APP::CONFIGURATION:
        os << "[CONFIGURATION]: ";
        break;
    }
    return os;
}

void log( const std::string &msg ) {
    log( LOG_APP::APPLICATION, msg );
}

void log( const LOG_APP &app, const std::string &msg ) {
    auto in_time_t = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() );

    std::cout << std::put_time( std::localtime( &in_time_t ), "%Y-%m-%d %X ") << app << msg << std::endl;
}
