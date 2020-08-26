#ifndef STRING_HELPERS_HPP_
#define STRING_HELPERS_HPP_

#include <string>

namespace std {
    std::string to_string( PPP_FSM_STATE state );
}

std::ostream& operator<<( std::ostream &stream, const PPP_FSM_STATE &state ); 
std::ostream& operator<<( std::ostream &stream, const PPPOEDISC_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const ETHERNET_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const RADIUS_CODE &code ); 
std::ostream& operator<<( std::ostream &stream, const RadiusPacket *pkt );

#endif