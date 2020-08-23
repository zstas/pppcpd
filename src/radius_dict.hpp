#ifndef RADIUS_DICT_HPP
#define RADIUS_DICT_HPP

enum class RADIUS_TYPE_T : uint8_t {
    STRING,
    INTEGER,
    IPADDR,
    OCTETS,
    VSA,
    ERROR
};

struct radius_attribute_t {
    std::string name;
    RADIUS_TYPE_T type;
    std::map<int32_t,std::string> values;

    radius_attribute_t( std::string n, RADIUS_TYPE_T t ):
        name( std::move( n ) ),
        type( t )
    {}

    std::string getValueString( uint8_t attr_id, int value ) const;
};

using attributes_t = std::map<uint8_t,radius_attribute_t>;

class RadiusDict {
public:
    RadiusDict( const std::vector<std::string> &files );
    std::tuple<uint8_t,uint32_t> getIdByName( const std::string &attr ) const;
    std::pair<std::string,RADIUS_TYPE_T> getAttrById( uint8_t id, uint32_t vendor = 0 ) const;

    int getValueByName( const std::string &attr, const std::string &text ) const;
    
private:
    void parseFreeradDict( const std::string &path );

    attributes_t attrs;
    std::map<std::string,uint32_t> vendors;
    std::map<uint32_t,attributes_t> vsa;
};

#endif