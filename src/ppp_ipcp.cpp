#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

std::string IPCP_FSM::send_conf_req() {
    log( "send_conf_req current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return "Cannot send conf req for unexisting session";
    }
    auto &session = sessIt->second;
    Packet pkt{};
    pkt.bytes.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + 256 );
    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;
    pkt.eth->ethertype = htons( ETH_PPPOE_SESSION );
    // Fill pppoe part
    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );
    pkt.pppoe_session->version = 1;
    pkt.pppoe_session->type = 1;
    pkt.pppoe_session->ppp_protocol = htons( static_cast<uint16_t>( PPP_PROTO::LCP ) );
    pkt.pppoe_session->code = PPPOE_CODE::SESSION_DATA;
    pkt.pppoe_session->session_id = htons( session_id );

    // Fill IPCP part; here we just can use lcp header
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );
    pkt.lcp->code = LCP_CODE::CONF_REQ;
    pkt.lcp->identifier = pkt_id;
    // Fill LCP options
    auto ipcpOpts = 0;
    auto ipad = reinterpret_cast<IPCP_OPT_4B*>( pkt.lcp->getPayload() );
    ipad->set( IPCP_OPTIONS::IP_ADDRESS, 0x64400001 );
    ipcpOpts += ipad->len;

    // After all fix lenght in headers
    pkt.lcp->length = htons( sizeof( PPP_LCP ) + ipcpOpts );
    pkt.pppoe_session->length = htons( sizeof( PPP_LCP ) + ipcpOpts + 2 ); // plus 2 bytes of ppp proto
    pkt.bytes.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) + ipcpOpts  );
    printHex( pkt.bytes );

    // Send this CONF REQ
    ppp_outcoming.push( pkt.bytes );

    return "";
}
