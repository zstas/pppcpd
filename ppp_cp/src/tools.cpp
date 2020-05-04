#include "main.hpp"

std::string random_string( size_t length )
{
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

void printHex( std::vector<uint8_t> pkt ) {
    for( auto &byte: pkt ) {
        printf( "%02x ", byte );
    }
    printf( "\n" );
}

uint32_t random_uin32_t() {
    std::random_device rd;
    std::mt19937_64 eng( rd() );
    
    std::uniform_int_distribution<uint32_t> distr;
    return distr( eng );
}

uint16_t bswap16( uint16_t value ) noexcept {
    return __builtin_bswap16( value );
}

uint32_t bswap32( uint32_t value ) noexcept {
    return __builtin_bswap32( value );
}