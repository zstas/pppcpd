#include "main.hpp"

std::tuple<std::vector<uint8_t>,std::string> ppp::processPPP( Packet inPkt ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( ETHERNET_HDR ) + 128 );

    //ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    inPkt.eth = reinterpret_cast<ETHERNET_HDR*>( inPkt.bytes.data() );
    log( "Ethernet packet:\n" + ether::to_string( inPkt.eth ) );
    if( inPkt.eth->ethertype != htons( ETH_PPPOE_SESSION ) ) {
        return { std::move( reply ), "Not pppoe session packet" };
    }

    inPkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.eth->getPayload() );
    switch( static_cast<PPP_PROTO>( ntohs( inPkt.pppoe_session->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        log( "proto LCP" );
        inPkt.lcp = reinterpret_cast<PPP_CP<LCP_CODE>*>( inPkt.pppoe_session->getPayload() );
        return ppp::processLCP( inPkt.lcp );
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