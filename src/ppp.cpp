#include "main.hpp"

std::tuple<std::vector<uint8_t>,std::string> ppp::processPPP( std::vector<uint8_t> pkt ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( ETHERNET_HDR ) + 128 );

    printHex( pkt );
    ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    log( "Ethernet packet:\n" + ether::to_string( eth ) );
    if( eth->ethertype != htons( ETH_PPPOE_SESSION ) ) {
        return { std::move( reply ), "Not pppoe session packet" };
    }

    PPPOESESSION_HDR *ppp = reinterpret_cast<PPPOESESSION_HDR*>( pkt.data() + sizeof( ETHERNET_HDR ) );
    switch( static_cast<PPP_PROTO>( ntohs( ppp->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        log( "proto LCP" );
        return ppp::processLCP( reinterpret_cast<PPP_CP<LCP_CODE>*>( pkt.data() + sizeof( ETHERNET_HDR ) + sizeof( PPPOESESSION_HDR ) ) );
        break;
    case PPP_PROTO::IPCP:
        log( "proto IPCP" );
        break;
    default:
        log( "unknown proto" );
    }

    return { std::move( reply ), "" };
}

std::tuple<std::vector<uint8_t>,std::string> ppp::processLCP( PPP_CP<LCP_CODE> *lcp ) {
    std::vector<uint8_t> reply;
    switch( lcp->code ) {
    case LCP_CODE::CONF_REQ:
        log("CONF REQ");
        break;
    default:
        log("another code");
    }
    return { std::move( reply ), "" };
}