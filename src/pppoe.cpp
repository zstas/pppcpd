#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

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

std::tuple<std::vector<uint8_t>,std::string> pppoe::processPPPOE( Packet inPkt ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( ETHERNET_HDR ) + sizeof( PPPOEDISC_HDR ) + 128 );

    inPkt.eth = reinterpret_cast<ETHERNET_HDR*>( inPkt.bytes.data() );
    if( inPkt.eth->ethertype != htons( ETH_PPPOE_DISCOVERY ) ) {
        return { std::move( reply ), "Not pppoe discovery packet" };
    }

    inPkt.pppoe_discovery = reinterpret_cast<PPPOEDISC_HDR*>( inPkt.eth->getPayload() );

    reply.resize( sizeof( ETHERNET_HDR ) + sizeof( PPPOEDISC_HDR ) );
    log( "Incoming " + std::to_string( inPkt.pppoe_discovery ) );
    
    ETHERNET_HDR *rep_eth = reinterpret_cast<ETHERNET_HDR*>( reply.data() );
    rep_eth->ethertype = htons( ETH_PPPOE_DISCOVERY );
    rep_eth->dst_mac = inPkt.eth->src_mac;

    PPPOEDISC_HDR *rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->type = 1;
    rep_pppoe->version = 1;
    rep_pppoe->session_id = 0;
    rep_pppoe->length = 0;

    // Starting to prepare the answer
    switch( inPkt.pppoe_discovery->code ) {
    case PPPOE_CODE::PADI:
        log( "Processing PADI packet" );
        rep_pppoe->code = PPPOE_CODE::PADO;
        break;
    case PPPOE_CODE::PADR:
        log( "Processing PADR packet" );
        rep_pppoe->code = PPPOE_CODE::PADS;
        if( const auto &[ sid, err ] = runtime->allocateSession( inPkt.eth->src_mac ); !err.empty() ) {
            return { std::move( reply ), "Cannot process PPPOE pkt: " + err };
        } else {
            log( "Session " + std::to_string( sid ) + " is UP!" );
            rep_pppoe->session_id = htons( sid );
        }
        break;
    case PPPOE_CODE::PADT:
        log( "Processing PADT packet" );
        if( const auto &err = runtime->deallocateSession( inPkt.eth->src_mac, ntohs( inPkt.pppoe_discovery->session_id ) ); !err.empty() ) {
            log( "Cannot terminate session: " + err );
        } else {
            log( "Terminated session " + ntohs( inPkt.pppoe_discovery->session_id ) );
        }
        return { std::move( reply ), "Received PADT, send nothing" };
    default:
        log( "Incorrect code for packet" );
        return { std::move( reply ), "Incorrect code for packet" };
    }

    // Parsing tags
    std::optional<std::string> chosenService;
    std::optional<std::string> hostUniq;
    if( auto const &[ tags, error ] = pppoe::parseTags( inPkt.bytes ); !error.empty() ) {
        return { std::move( reply ), "Cannot parse tags cause: " + error };
    } else {
        for( auto &[ tag, val ]: tags ) {
            switch( tag ) {
            case PPPOE_TAG::AC_NAME:
                break;
            case PPPOE_TAG::AC_COOKIE:
                break;
            case PPPOE_TAG::HOST_UNIQ:
                if( !val.empty() ) {
                    hostUniq = val;
                }
                break;
            case PPPOE_TAG::VENDOR_SPECIFIC:
                break;
            case PPPOE_TAG::RELAY_SESSION_ID:
                break;
            case PPPOE_TAG::AC_SYSTEM_ERROR:
                break;
            case PPPOE_TAG::GENERIC_ERROR:
                break;
            case PPPOE_TAG::SERVICE_NAME:
                // RFC 2516:
                // If the Access Concentrator can not serve the PADI it MUST NOT respond with a PADO.
                if( !val.empty() && val != runtime->pppoe_conf->service_name ) {
                    if( runtime->pppoe_conf->ignoreServiceName ) {
                        log( "Service name is differ, but we can ignore it" );
                        chosenService = val;
                    } else {
                        return { std::move( reply ), "Cannot serve \"" + val + "\" service, because in policy only \"" + runtime->pppoe_conf->service_name + "\"" };
                    }
                }
                break;
            case PPPOE_TAG::SERVICE_NAME_ERROR:
                break;
            case PPPOE_TAG::END_OF_LIST:
                break;
            }
        }
    }

    // Inserting tags
    auto taglen = 0;
    taglen += pppoe::insertTag( reply, PPPOE_TAG::AC_NAME, runtime->pppoe_conf->ac_name );

    if( chosenService.has_value() ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::SERVICE_NAME, chosenService.value() );
    } else {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::SERVICE_NAME, runtime->pppoe_conf->service_name );
    }

    if( hostUniq.has_value() ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::HOST_UNIQ, hostUniq.value() );
    }

    if( runtime->pppoe_conf->insertCookie ) {
        taglen += pppoe::insertTag( reply, PPPOE_TAG::AC_COOKIE, random_string( 16 ) );
    }

    // In case of vector is increased
    rep_pppoe = reinterpret_cast<PPPOEDISC_HDR*>( reply.data() + sizeof( ETHERNET_HDR ) );
    rep_pppoe->length = htons( taglen );
    log( "Outcoming " + std::to_string( rep_pppoe ) );

    return { std::move( reply ), "" };
}
