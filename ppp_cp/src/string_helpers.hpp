#include <string>

namespace std {
    std::string to_string( PPP_FSM_STATE state );
    std::string to_string( ETHERNET_HDR *eth );
}

std::ostream& operator<<( std::ostream &stream, const PPP_FSM_STATE &state ); 
std::ostream& operator<<( std::ostream &stream, const PPPOEDISC_HDR &disc ); 
