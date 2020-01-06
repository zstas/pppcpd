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


uint8_t pppoe::insertTag( std::vector<uint8_t> &pkt, PPPOE_TAG tag, const std::string &val ) {
    std::vector<uint8_t> tagvec;
    tagvec.resize( 4 );
    auto tlv = reinterpret_cast<PPPOEDISC_TLV*>( tagvec.data() );
    tlv->type = htons( static_cast<uint16_t>( tag ) );
    tlv->length = htons( val.size() );
    tagvec.insert( tagvec.end(), val.begin(), val.end() );
    pkt.insert( pkt.end(), tagvec.begin(), tagvec.end() );     

    return tagvec.size();
}

std::tuple<std::map<PPPOE_TAG,std::string>,std::string> pppoe::parseTags( std::vector<uint8_t> &pkt ) {
    std::map<PPPOE_TAG,std::string> tags;
    PPPOEDISC_TLV *tlv = nullptr;
    auto offset = pkt.data() + sizeof( ETHERNET_HDR) + sizeof( PPPOEDISC_HDR );
    while( true ) {
        tlv = reinterpret_cast<PPPOEDISC_TLV*>( offset );
        auto tag = PPPOE_TAG { ntohs( tlv->type ) };
        auto len = ntohs( tlv->length );
        std::string val;

        if( tag == PPPOE_TAG::END_OF_LIST ) {
            return { std::move( tags ), "" };   
        }

        if( len > 0 ) {
            val = std::string { reinterpret_cast<char*>( &tlv->value ), len };
        }

        if( auto const &[ it, ret ] = tags.emplace( tag, val ); !ret ) {
            return { std::move( tags ), "Cannot insert tag " + std::to_string( ntohs( tlv->type ) ) + " in tag map" };
        }

        offset += 4 + len;
        if( offset >= pkt.end().base() ) {
            break;
        }
    }
    return { std::move( tags ), "" };
}