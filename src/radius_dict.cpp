#include "main.hpp"

RadiusDict::RadiusDict( const std::vector<std::string> &files ) {
    for( auto const &f: files ) {
        parseFreeradDict( f );
    }
}

void RadiusDict::parseFreeradDict( const std::string &path ) {
std::ifstream file { path };
    if( !file.is_open() ) {
        return;
    }

    std::string line; 
    uint32_t current_vendor = 0;

    while( getline( file, line ) ) {
        if( line.front() == '#' ) {
            continue;
        }
        if( line.find( "ATTRIBUTE" ) == std::string::npos &&
            line.find( "VALUE" ) == std::string::npos &&
            line.find( "VENDOR" ) == std::string::npos && 
            line.find( "BEGIN-VENDOR" ) == std::string::npos &&
            line.find( "END-VENDOR" ) == std::string::npos ) {
            continue;
        }
        std::vector<std::string> out;
        boost::split( out, line, boost::is_any_of(" \t") );
        std::remove_if( out.begin(), out.end(), []( const std::string &r )->bool { return r.size() == 0; } );
        
        if( out[ 0 ].find( "ATTRIBUTE" ) == 0 ) {
            if( out.size() < 4 ) {
                continue;
            }
            uint8_t attr_id = std::stoi( out[ 2 ] );
            RADIUS_TYPE_T type { RADIUS_TYPE_T::ERROR };
            if( out[ 3 ].find( "string" ) == 0 ) { type = RADIUS_TYPE_T::STRING; }
            if( out[ 3 ].find( "octets" ) == 0 ) { type = RADIUS_TYPE_T::OCTETS; }
            if( out[ 3 ].find( "ipaddr" ) == 0 ) { type = RADIUS_TYPE_T::IPADDR; }
            if( out[ 3 ].find( "integer" ) == 0 ) { type = RADIUS_TYPE_T::INTEGER; }
            if( out[ 3 ].find( "vsa" ) == 0 ) { type = RADIUS_TYPE_T::VSA; }
            if( current_vendor == 0 ) {
                attrs.emplace( std::piecewise_construct, std::forward_as_tuple( attr_id ), std::forward_as_tuple( out[1], type ) );
            } else {
                vsa[ current_vendor ].emplace( std::piecewise_construct, std::forward_as_tuple( attr_id ), std::forward_as_tuple( out[1], type ) );
            }
        } else if( out[ 0 ].find( "VALUE" ) == 0 ) {
            if( out.size() < 4 ) {
                continue;
            }
            int32_t attr_val = std::stoi( out[ 3 ] );
            attributes_t &attrs_to_find = current_vendor == 0 ? attrs : vsa[ current_vendor ];
            for( auto &[ k, v ]: attrs_to_find ) {
                if( out[ 1 ].find( v.name ) == 0 ) {
                    v.values.emplace( attr_val, out[ 2 ] );
                }
            }
        } else if( out[ 0 ].find( "VENDOR" ) == 0 ) {
            if( out.size() < 3 ) {
                continue;
            }
            uint32_t vend_id = std::stoi( out[ 2 ] );
            if( auto const &[ it, ret ] = vendors.emplace( out[ 1 ], vend_id ); !ret ) {
                std::cerr << "Cannot emplace vendor " << out[ 1 ] << " with id " << out[ 2 ] << std::endl;
            }
        } else if( out[ 0 ].find( "BEGIN-VENDOR" ) == 0 ) {
            if( out.size() < 2 ) {
                continue;
            }
            if( auto const &it = vendors.find( out[ 1 ] ); it != vendors.end() ) {
                current_vendor = it->second;
            }
        } else if( out[ 0 ].find( "END-VENDOR" ) == 0 ) {
            current_vendor = 0;
        }
    }
}

std::tuple<uint8_t,uint32_t> RadiusDict::getIdByName( const std::string &attr ) const {
    for( auto const &[ k, v ]: attrs ) {
        if( v.name == attr ) {
            return { k, 0 };
        }
    }
    for( auto const &[ vendid, vendattr ]: vsa ) {
        for( auto const &[ k, v ]: vendattr) {
            if( v.name == attr ) {
                return { k, vendid };
            }
        }
    }
    return { 0, 0 };
}

std::pair<std::string,RADIUS_TYPE_T> RadiusDict::getAttrById( uint8_t id, uint32_t v ) const {
    if( v == 0 ) {
        if( auto const &it = attrs.find( id ); it != attrs.end() ) {
            return { it->second.name, it->second.type };
        }
    } else {
        auto vit = vsa.find( v );
        if( vit == vsa.end() ) {
            return { {}, RADIUS_TYPE_T::ERROR };
        }
        auto &att = vit->second;
        if( auto const &it = att.find( id ); it != att.end() ) {
            return { it->second.name, it->second.type };
        } 
    }
    return { {}, RADIUS_TYPE_T::ERROR };
}

std::string radius_attribute_t::getValueString( uint8_t attr_id, int value ) const {
    if( auto const &valIt = values.find( value ); valIt != values.end() ) {
        return valIt->second;
    }
    return {};
}

int RadiusDict::getValueByName( const std::string &attr, const std::string &text ) const {
    for( auto const &[ k, v ]: attrs ) {
        if( v.name != attr ) {
            continue;
        }

        for( auto const &[ index, value ]: v.values ) {
            if( value == text ) {
                return index;
            }
        }
    }
    return 0;
}