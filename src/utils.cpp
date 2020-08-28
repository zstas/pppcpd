#include <boost/random/random_device.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>

#include "main.hpp"

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

std::string password_pap_process( const authenticator_t &auth, const std::string secret, std::string pass ) {
    std::string result;

    auto nlen = pass.length();
    if( nlen % 16 != 0 ) {
        nlen += 16 - pass.length() % 16;
    }

    while( pass.size() != nlen ) {
        pass.push_back( '\0' );
    }

    auto b1 = secret;
    b1.insert( b1.end(), auth.begin(), auth.end() );
    b1 = md5( b1 );

    for( int i = 0; i < nlen / 16; i++ ) {
        std::array<uint8_t,16> c1;
        for( int j = 0; j < 16; j++ ) {
            c1[ j ] = b1[ j ] ^ pass[ 16*i + j ];
        }    
        result.insert( result.end(), c1.begin(), c1.end() );
        b1 = secret;
        b1.insert( b1.end(), c1.begin(), c1.end() );
        b1 = md5( b1 );
    }

    return result;
}

std::string acct_auth_process( const std::vector<uint8_t> &pkt, const std::vector<uint8_t> req_attrs, const std::string &secret ) {
    std::string check { pkt.begin(), pkt.begin() + 4 };
    check.reserve( 128 );
    check.insert( check.end(), 16, 0 );
    check.insert( check.end(), req_attrs.begin(), req_attrs.end() );
    check.insert( check.end(), secret.begin(), secret.end() );
    return md5( check );
}

std::string std::to_string( const RADIUS_CODE &code ) {
    switch( code ) {
    case RADIUS_CODE::ACCESS_REQUEST:
        return "ACCESS_REQUEST";
    case RADIUS_CODE::ACCESS_ACCEPT:
        return "ACCESS_ACCEPT";
    case RADIUS_CODE::ACCESS_REJECT:
        return "ACCESS_REJECT";
    case RADIUS_CODE::ACCOUNTING_REQUEST:
        return "ACCOUNTING_REQUEST";
    case RADIUS_CODE::ACCOUNTING_RESPONSE:
        return "ACCOUNTING_RESPONSE";
    case RADIUS_CODE::ACCESS_CHALLENGE:
        return "ACCESS_CHALLENGE";
    default:
        break;
    }
    return {};
}