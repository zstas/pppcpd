#include "main.hpp"

std::ostream& operator<<( std::ostream &stream, const mac_t &mac ) {
    stream << std::hex << std::setw( 2 ) << std::setfill( '0' );
    stream << ( int )mac[ 0 ] << ":";
    stream << ( int )mac[ 1 ] << ":";
    stream << ( int )mac[ 2 ] << ":";
    stream << ( int )mac[ 3 ] << ":";
    stream << ( int )mac[ 4 ] << ":";
    stream << ( int )mac[ 5 ];
    return stream;
}