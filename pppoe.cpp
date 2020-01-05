#include "main.hpp"

std::string pppoe::to_string( const PPPOEDISC_HDR *hdr ) {
    std::ostringstream out;
    out << "pppoe discovery packet:" << std::endl;
    out << "type: " << hdr->type << std::endl;
    out << "version: " << hdr->version << std::endl;
    out << "code: ";
    switch( hdr->code ) {
        case PPPOE_CODE::PADI:
            out << "padi discover" << std::endl; break;
        case PPPOE_CODE::PADO:
            out << "pado offer" << std::endl; break;
        case PPPOE_CODE::PADR:
            out << "padr request" << std::endl; break;
        case PPPOE_CODE::PADS:
            out << "pads serice" << std::endl; break;
        default:
            out << "uknown code" << std::endl;
    }
    out << "session id: " << hdr->session_id << std::endl;
    out << "length: " << htons( hdr->length ) << std::endl;

    return out.str();
}