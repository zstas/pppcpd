#include "main.hpp"

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
    auto it = v.begin();
    while( it != v.end() ) {
        ret.emplace_back( v, it );
        it += ret.back().getSize();
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