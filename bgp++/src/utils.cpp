#include "main.hpp"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

std::ostream& operator<<( std::ostream & os, const LOG_APP & app ) {
    switch( app ) {
    case LOG_APP::APPLICATION:
        os << "[application]: ";
        break;
    case LOG_APP::FSM:
        os << "[fsm]: ";
        break;
    case LOG_APP::CONNECTION:
        os << "[connection]: ";
        break;
    case LOG_APP::CONFIGURATION:
        os << "[configuration]: ";
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

uint16_t bswap16( uint16_t value ) noexcept {
    return __builtin_bswap16( value );
}

uint32_t bswap32( uint32_t value ) noexcept {
    return __builtin_bswap32( value );
}
