#ifndef RADIUS_AVP_HPP
#define RADIUS_AVP_HPP

#include "net_integer.hpp"

#define RADIUS_VSA 26

struct RadiusDict;

struct AVP {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> value;
    uint32_t vendor;

    explicit AVP( const RadiusDict &dict, const std::string &attr, BE32 v );
    explicit AVP( const RadiusDict &dict, const std::string &attr, BE16 v );
    explicit AVP( const RadiusDict &dict, const std::string &attr, const std::string &s );
    explicit AVP( const std::vector<uint8_t> &v, std::vector<uint8_t>::iterator it );

    size_t getSize() const;

    template<typename T>
    std::tuple<T, bool> getVal() const;

    bool operator<( const AVP &r ) const;

    std::vector<uint8_t> serialize() const;
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