#include <tuple>
#include <vector>
#include <set>
#include <map>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>

using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

#include "radius_avp.hpp"
#include "radius_dict.hpp"
#include "net_integer.hpp"
#include "log.hpp"
#include "string_helpers.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

AVP::AVP( const RadiusDict &dict, const std::string &attr, BE32 v ) {
    auto [ id, vendorid ] = dict.getIdByName( attr );
    type = id;
    vendor = vendorid;
    value.resize( sizeof( BE32 ) );
    *reinterpret_cast<uint32_t*>( value.data() ) = v.raw();
    length = sizeof( type ) + sizeof( length ) + value.size();
}

AVP::AVP( const RadiusDict &dict, const std::string &attr, BE16 v ) {
    auto [ id, vendorid ] = dict.getIdByName( attr );
    type = id;
    vendor = vendorid;
    value.resize( sizeof( BE16 ) );
    *reinterpret_cast<uint16_t*>( value.data() ) = v.raw();
    length = sizeof( type) + sizeof( length ) + value.size();
}

AVP::AVP( const RadiusDict &dict, const std::string &attr, const std::string &s ) {
    auto [ id, vendorid ] = dict.getIdByName( attr );
    type = id;
    vendor = vendorid;
    if( uint32_t i = dict.getValueByName( attr, s ); i != 0 ) {
        value.resize( sizeof( BE32 ) );
        *reinterpret_cast<uint32_t*>( value.data() ) = BE32( i ).raw();    
    } else {
        value = { s.begin(), s.end() };
    }
    length = sizeof( type) + sizeof( length ) + value.size();
}

AVP::AVP( const std::vector<uint8_t> &v, std::vector<uint8_t>::iterator it ) {
    if( ( v.end() - it ) < 2 ) {
        throw std::runtime_error( "No room for parsing VSA" );
    }

    type = *it;
    it++;
    original_len = *it;
    if( type == RADIUS_VSA ) {
        it++; //pass the length
        vendor = bswap( *( reinterpret_cast<uint32_t*>( &( *it ) ) ) );
        it += 4;
        type = *it;
        it++;
    }
    length = *it;
    it++;
    value = { it, it + length - 2 };
}

size_t AVP::getSize() const {
    return original_len;
}

bool AVP::operator<( const AVP &r ) const {
    return type < r.type;
}

std::vector<uint8_t> AVP::serialize() const {
    std::vector<uint8_t> ret;
    ret.reserve( sizeof( type ) + sizeof( length ) + length + 10 );
    if( vendor == 0 ) {
        ret.push_back( type );
    } else {
        ret.push_back( sizeof( type) + sizeof( length ) + sizeof( vendor ) + sizeof( type ) + sizeof( length ) + value.size() );
        std::array<uint8_t,4> vend_buf;
        *reinterpret_cast<uint32_t*>( &vend_buf ) = vendor;
        ret.insert( ret.end(), vend_buf.begin(), vend_buf.end() );
        ret.push_back( type );
    }
    ret.push_back( length );
    ret.insert( ret.end(), value.begin(), value.end() );
    return ret;
}

template<>
std::tuple<std::string, bool> AVP::getVal<std::string>() const {
    return { { value.begin(), value.end() }, true };
}

template<>
std::tuple<BE32, bool> AVP::getVal<BE32>() const {
    if( value.size() != 4 ) {
        return { BE32( 0 ), false };
    } 
    auto raw = Raw{ *reinterpret_cast<const uint32_t*>( value.data() ) };
    return { BE32( raw ), true };
}

template<>
std::tuple<BE16, bool> AVP::getVal<BE16>() const {
    if( value.size() != 4 ) {
        return { BE16( 0 ), false };
    } 
    auto raw = Raw{ *reinterpret_cast<const uint16_t*>( value.data() ) };
    return { BE16( raw ), true };
}


std::vector<AVP> parseAVP( std::vector<uint8_t> &v ) {
    std::vector<AVP> ret;
    try {
        auto it = v.begin();
        while( it != v.end() ) {
            ret.emplace_back( v, it );
            it += ret.back().getSize();
        }
    } catch( std::exception &e ) {
        runtime->logger->logError() << LOGS::RADIUS << e.what() << std::endl;
    }

    return ret;
}

std::string printAVP( const RadiusDict &dict, const AVP &avp ) {
    std::string out;

    auto const &at = dict.getAttrById( avp.type );
    if( at.first.empty() || at.second == RADIUS_TYPE_T::ERROR ) {
        return "UKNOWN ATTRIBUTE";
    }

    out += "ATTR: " + at.first + "\t\t";
    auto &type = at.second;
    out += "VALUE: ";
    switch( type ) {
    case RADIUS_TYPE_T::INTEGER:
        if( auto const &[ ret, success ] = avp.getVal<BE32>(); success ) {
            out += std::to_string( ret.native() );
        } else {
            out += "ERROR";
        }
        break;
    case RADIUS_TYPE_T::STRING:
        if( auto const &[ ret, success ] = avp.getVal<std::string>(); success ) {
            out += ret;
        } else {
            out += "ERROR";
        }
        break;
    case RADIUS_TYPE_T::IPADDR:
        if( auto const &[ ret, success ] = avp.getVal<BE32>(); success ) {
            out += address_v4_t{ ret.native() }.to_string();
        } else {
            out += "ERROR";
        }
        break;
    default:
        out += "UNKNOWN";
        break;
    }

    return out;
}

std::vector<uint8_t> serializeAVP( const std::set<AVP> &avp ) {
    std::vector<uint8_t> ret;

    for( auto const &a: avp ) {
        auto temp = a.serialize();
        ret.insert( ret.end(), temp.begin(), temp.end() );
    }
    return ret;
}