#include "main.hpp"

std::ostream& operator<<( std::ostream &stream, const mac_t &mac ) {
    char buf[ 18 ];
    snprintf( buf, sizeof( buf ), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    return stream << buf;
}