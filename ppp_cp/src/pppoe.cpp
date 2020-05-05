#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ pppoe_outcoming;

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
    auto offset = pkt.data();
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

static std::string process_padi( std::vector<uint8_t> &inPkt, std::vector<uint8_t> &outPkt, mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan ) {
    log( "Processing PADI packet" );

    outPkt.resize( sizeof( PPPOEDISC_HDR ) + 128 );
    PPPOEDISC_HDR *rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( outPkt.data() );
    
    rep_pppoe->type = 1;
    rep_pppoe->version = 1;
    rep_pppoe->session_id = 0;
    rep_pppoe->length = 0;    
    rep_pppoe->code = PPPOE_CODE::PADO;
    
    if( inPkt.size() < sizeof( PPPOEDISC_HDR ) ) {
        return "Too small packet";
    }
    inPkt.erase( inPkt.begin(), inPkt.begin() + sizeof( PPPOEDISC_HDR) );
    auto [ tags, err ] = pppoe::parseTags( inPkt );
    if( !err.empty() ) {
        return "Cannot process PADI: " + err;
    }

    // Inserting tags
    auto taglen = 0;

    // At first we need to insert AC NAME
    taglen += pppoe::insertTag( outPkt, PPPOE_TAG::AC_NAME, runtime->pppoe_conf->ac_name );

    // Check for HOST UNIQ
    if( auto const &tagIt = tags.find( PPPOE_TAG::HOST_UNIQ ); tagIt != tags.end() ) {
        taglen += pppoe::insertTag( outPkt, PPPOE_TAG::HOST_UNIQ, tagIt->second );
    }

    // Check for SERVICE NAME
    if( auto const &tagIt = tags.find( PPPOE_TAG::SERVICE_NAME ); tagIt != tags.end() ) {
        std::string selected_service;

        for( auto const &service: runtime->pppoe_conf->service_name ) {
            if( service == tagIt->second ) {
                selected_service = tagIt->second;
                break;
            }
        }

        if( selected_service.empty() && runtime->pppoe_conf->ignoreServiceName ) {
            selected_service = tagIt->second;
        }

        if( selected_service.empty() && !runtime->pppoe_conf->ignoreServiceName ) {
            return "Wrong service name";
        }

        taglen += pppoe::insertTag( outPkt, PPPOE_TAG::SERVICE_NAME, selected_service );
    }

    // Check our policy if we need to insert AC COOKIE
    std::string cookie;
    if( runtime->pppoe_conf->insertCookie ) {
        cookie = random_string( 16 );
        taglen += pppoe::insertTag( outPkt, PPPOE_TAG::AC_COOKIE, cookie );
    }

    if( auto const & err = runtime->pendeSession( mac, outer_vlan, inner_vlan, cookie); !err.empty() ) {
        return "Cannot pende session: " + err;
    }

    rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( outPkt.data() );
    rep_pppoe->length = bswap16( taglen );

    return {};
}

static std::string process_padr( std::vector<uint8_t> &inPkt, std::vector<uint8_t> &outPkt ) {
    log( "Processing PADR packet" );
        
    outPkt.resize( sizeof( PPPOEDISC_HDR ) );
    
    PPPOEDISC_HDR *rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( outPkt.data() );

    rep_pppoe->type = 1;
    rep_pppoe->version = 1;
    rep_pppoe->session_id = 0;
    rep_pppoe->length = 0;
    rep_pppoe->code = PPPOE_CODE::PADS;
    
    if( inPkt.size() < sizeof( PPPOEDISC_HDR ) ) {
        return "Too small packet";
    }
    inPkt.erase( inPkt.begin(), inPkt.begin() + sizeof( PPPOEDISC_HDR) );
    auto tags = pppoe::parseTags( inPkt );

    return {};
}

std::string processPPPOE( std::vector<uint8_t> &inPkt, mac_t mac, uint16_t outer_vlan, uint16_t inner_vlan ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( PPPOEDISC_HDR ) + 128 );

    PPPOEDISC_HDR *disc = reinterpret_cast<PPPOEDISC_HDR*>( inPkt.data() );

    log( "Incoming " + std::to_string( disc ) );
    
    // Starting to prepare the answer
    switch( disc->code ) {
    case PPPOE_CODE::PADI:
        process_padi();
        break;
    case PPPOE_CODE::PADR:
        process_padr();
        break;
    case PPPOE_CODE::PADT:
        log( "Processing PADT packet" );
        if( const auto &err = runtime->deallocateSession( inPkt.eth->src_mac, ntohs( inPkt.pppoe_discovery->session_id ) ); !err.empty() ) {
            log( "Cannot terminate session: " + err );
        } else {
            log( "Terminated session " + std::to_string( ntohs( inPkt.pppoe_discovery->session_id ) ) );
        }
        return "Received PADT, send nothing";
    default:
        log( "Incorrect code for packet" );
        return "Incorrect code for packet";
    }

    // In case of vector is increased
    rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->length = htons( taglen );
    log( "Outcoming " + std::to_string( rep_pppoe ) );

    pppoe_outcoming.push( std::move( reply ) );

    return {};
}
