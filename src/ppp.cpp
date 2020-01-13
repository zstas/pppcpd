#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

std::string ppp::processPPP( Packet inPkt ) {
    inPkt.eth = reinterpret_cast<ETHERNET_HDR*>( inPkt.bytes.data() );
    //log( "Ethernet packet:\n" + ether::to_string( inPkt.eth ) );
    if( inPkt.eth->ethertype != ntohs( ETH_PPPOE_SESSION ) ) {
        return "Not pppoe session packet";
    }

    inPkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.eth->getPayload() );

    // Determine this session
    std::array<uint8_t,8> key;
    std::memcpy( key.data(), inPkt.eth->src_mac.data(), 6 );
    uint16_t sessionId = ntohs( inPkt.pppoe_session->session_id );
    *reinterpret_cast<uint16_t*>( &key[ 6 ] ) = sessionId;

    auto const &sessionIt = runtime->sessions.find( sessionId );
    if( sessionIt == runtime->sessions.end() ) {
        return "Cannot find this session in runtime";
    }
    auto &session = sessionIt->second;

    inPkt.lcp = reinterpret_cast<PPP_LCP*>( inPkt.pppoe_session->getPayload() );

    switch( static_cast<PPP_PROTO>( ntohs( inPkt.pppoe_session->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        log( "proto LCP for session " + std::to_string( session.session_id ) );
        session.lcp.receive( inPkt );
        break;
    case PPP_PROTO::IPCP:
        log( "proto IPCP" );
        session.ipcp.receive( inPkt );
        break;
    case PPP_PROTO::PAP:
        log( "proto PAP" );
        session.auth.receive( inPkt );
        break;
    default:
        log( "unknown proto" );
    }

    return "";
}
