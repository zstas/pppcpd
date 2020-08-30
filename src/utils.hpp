#ifndef UTILS_HPP
#define UTILS_HPP

#include <array>
#include <vector>
#include <string>

using authenticator_t = std::array<uint8_t,16>;

authenticator_t generateAuthenticator();
std::string md5( const std::string &v );
std::string md5_hex( const std::string &v );
std::string random_string( size_t length );
uint32_t random_uin32_t();
void printHex( std::vector<uint8_t> pkt );

#endif