#include <string>
#include <algorithm>
#include <random>

#define BOOST_UUID_COMPAT_PRE_1_71_MD5

#include <boost/random/random_device.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>

#include "utils.hpp"
#include "radius_packet.hpp"

using md5_t = boost::uuids::detail::md5;

authenticator_t generateAuthenticator() {
    boost::random::random_device rng;
    authenticator_t ret;

    rng.generate( ret.begin(), ret.end() );

    return ret;
}

std::string md5( const std::string &v ) {
    md5_t hash;
    md5_t::digest_type digest;

    hash.process_bytes( v.data(), v.size() );
    hash.get_digest( digest );
    const auto charDigest = reinterpret_cast<const char *>(&digest);

    return { charDigest, charDigest + sizeof( md5_t::digest_type ) };
}

std::string md5_hex( const std::string &v ) {
    auto hash = md5( v );
    std::string result;
    boost::algorithm::hex( v.begin(), v.end(), std::back_inserter( result ) );

    return result;
}

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
