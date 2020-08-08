#ifndef TOOLS_HPP_
#define TOOLS_HPP_

std::string random_string( size_t length );
uint32_t random_uin32_t();
void printHex( std::vector<uint8_t> pkt );
uint16_t bswap16( uint16_t value ) noexcept;

uint32_t bswap32( uint32_t value ) noexcept;

#endif