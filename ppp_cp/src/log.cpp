#include "main.hpp"
#include <chrono>
#include <ctime>

std::ostream& operator<<( std::ostream &os, const LOGL &l ) {
    switch( l ) {
    case LOGL::TRACE: return os << "[TRACE] ";
    case LOGL::DEBUG: return os << "[DEBUG] ";
    case LOGL::INFO: return os << "[INFO] ";
    case LOGL::WARN: return os << "[WARN] ";
    case LOGL::ERROR: return os << "[ERROR] ";
    case LOGL::ALERT: return os << "[ALERT] ";
    }
    return os;
}

std::ostream& operator<<( std::ostream &os, const LOGS &l ) {
    switch( l ) {
    case LOGS::AAA: return os << "[AAA] ";
    case LOGS::PACKET: return os << "[PACKET] ";
    case LOGS::PPPOED: return os << "[PPPOED] ";
    case LOGS::PPP: return os << "[PPP] ";
    case LOGS::LCP: return os << "[LCP] ";
    case LOGS::IPCP: return os << "[IPCP] ";
    case LOGS::PPP_AUTH: return os << "[PPP_AUTH] ";
    case LOGS::MAIN: return os << "[MAIN] ";
    case LOGS::VPP: return os << "[VPP] ";
    }
    return os;
}

void log( const std::string &msg ) {
    auto in_time_t = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() );

    std::cout << std::put_time( std::localtime( &in_time_t ), "%Y-%m-%d %X: ") << msg << std::endl;
}