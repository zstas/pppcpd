#include "main.hpp"

std::ostream& operator<<( std::ostream &stream, const mac_t &mac ) {
    auto flags = stream.flags();
    stream << std::hex; 
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 0 ] << ":";
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 1 ] << ":";
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 2 ] << ":";
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 3 ] << ":";
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 4 ] << ":";
    stream << std::setw( 2 ) << std::setfill( '0' ) << ( int )mac[ 5 ];
    stream.flags( flags );
    return stream;
}