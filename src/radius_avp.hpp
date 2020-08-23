#ifndef RADIUS_AVP_HPP
#define RADIUS_AVP_HPP

#include "radius_dict.hpp"

#define RADIUS_VSA 26

struct AVP {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> value;
    uint32_t vendor;

    explicit AVP( const RadiusDict &dict, const std::string &attr, BE32 v ) {
        auto [ id, vendorid ] = dict.getIdByName( attr );
        type = id;
        vendor = vendorid;
        value.resize( sizeof( BE32 ) );
        *reinterpret_cast<uint32_t*>( value.data() ) = v.raw();
        length = sizeof( type ) + sizeof( length ) + value.size();
    }

    explicit AVP( const RadiusDict &dict, const std::string &attr, BE16 v ) {
        auto [ id, vendorid ] = dict.getIdByName( attr );
        type = id;
        vendor = vendorid;
        value.resize( sizeof( BE16 ) );
        *reinterpret_cast<uint16_t*>( value.data() ) = v.raw();
        length = sizeof( type) + sizeof( length ) + value.size();
    }

    explicit AVP( const RadiusDict &dict, const std::string &attr, const std::string &s ) {
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

    explicit AVP( const std::vector<uint8_t> &v, std::vector<uint8_t>::iterator it ) {
        if( ( v.end() - it ) < 2 ) {
            return;
        }

        type = *it;
        it++;
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

    size_t getSize() const {
        return sizeof( type ) + sizeof( length ) + value.size();
    }

    template<typename T>
    std::tuple<T, bool> getVal() const;

    bool operator<( const AVP &r ) const {
        return type < r.type;
    }

    std::vector<uint8_t> serialize() const {
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
};

template<>
std::tuple<std::string, bool> AVP::getVal<std::string>() const;

template<>
std::tuple<BE32, bool> AVP::getVal<BE32>() const;

template<>
std::tuple<BE16, bool> AVP::getVal<BE16>() const;

std::vector<AVP> parseAVP( std::vector<uint8_t> &v );
std::string printAVP( const RadiusDict &dict, const AVP &avp );

std::vector<uint8_t> serializeAVP( const std::set<AVP> &avp );

#endif