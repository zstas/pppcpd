#include "main.hpp"


PPPoE_Discovery::PPPoE_Discovery( std::vector<uint8_t> pkt ) {
    type_version = pkt.at( 0 );
    code = PPPOE_CODE( pkt.at( 1 ) );
    session_id = *reinterpret_cast<uint16_t*>( &pkt.at( 2 ) );
    length = *reinterpret_cast<uint16_t*>( &pkt.at( 4 ) );
}

std::string PPPoE_Discovery::toString() const {
    std::string out;
    out += "pppoe discovery packet:\n";
    out += "version and type: " + std::to_string( type_version ) + "\n";
    out += "code: ";
    switch( code ) {
        case PPPOE_CODE::PADI:
            out += "padi discover\n"; break;
        case PPPOE_CODE::PADO:
            out += "pado offer\n"; break;
        case PPPOE_CODE::PADR:
            out += "padr request\n"; break;
        case PPPOE_CODE::PADS:
            out += "pads serice\n"; break;
        default:
            out += "uknown code\n";
    }
    out += "session id: " + std::to_string( session_id ) + "\n";
    out += "length: " + std::to_string( htons( length ) ) + "\n";

    return out;
}