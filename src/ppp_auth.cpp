#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

FSM_RET PPP_AUTH::receive( Packet &pkt ) {
    pkt.auth = reinterpret_cast<PPP_AUTH_HDR*>( pkt.pppoe_session->getPayload() );
    switch( pkt.auth->code ) {
    case PAP_CODE::AUTHENTICATE_REQ:
        return recv_auth_req( pkt );
        break;
    default:
        break;
    }
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET PPP_AUTH::recv_auth_req( Packet &pkt ) {
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send auth ack for unexisting session" };
    }
    auto &session = sessIt->second;

    uint8_t user_len = *( pkt.auth->getPayload() );
    std::string username { reinterpret_cast<char*>( pkt.auth->getPayload() + 1 ), reinterpret_cast<char*>( pkt.auth->getPayload() + 1 + user_len ) };
    uint8_t pass_len = *( pkt.auth->getPayload() + user_len + 1 );
    std::string password { reinterpret_cast<char*>( pkt.auth->getPayload() + 1 + user_len + 1 ), reinterpret_cast<char*>( pkt.auth->getPayload() + 1 + user_len + 1 + pass_len ) };

    session.username = username;

    if( runtime->aaa->startSession( username, password ) ) {
        return send_auth_ack( pkt );
    } else {
        return send_auth_nak( pkt );
    }
}

FSM_RET PPP_AUTH::send_auth_ack( Packet &pkt ) {
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send auth ack for unexisting session" };
    }
    auto &session = sessIt->second;

    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;

    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );

    // Fill PAP part
    pkt.auth = reinterpret_cast<PPP_AUTH_HDR*>( pkt.pppoe_session->getPayload() );
    pkt.auth->code = PAP_CODE::AUTHENTICATE_ACK;

    // append empty tag with message
    *pkt.auth->getPayload() = 0;
    pkt.auth->length = htons( sizeof( PPP_AUTH_HDR) + 1 );
    pkt.pppoe_session->length = htons( sizeof( PPP_AUTH_HDR) + 3 );

    // Send this packet
    ppp_outcoming.push( std::move( pkt.bytes ) );
    return { PPP_FSM_ACTION::LAYER_UP, "" };
}

FSM_RET PPP_AUTH::send_auth_nak( Packet &pkt ) {
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send auth nak for unexisting session" };
    }
    auto &session = sessIt->second;

    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;

    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );

    // Fill PAP part
    pkt.auth = reinterpret_cast<PPP_AUTH_HDR*>( pkt.pppoe_session->getPayload() );
    pkt.auth->code = PAP_CODE::AUTHENTICATE_NAK;

    // append empty tag with message
    *pkt.auth->getPayload() = 0;
    pkt.auth->length = htons( sizeof( PPP_AUTH_HDR) + 1 );
    pkt.pppoe_session->length = htons( sizeof( PPP_AUTH_HDR) + 3 );

    // Send this packet
    ppp_outcoming.push( std::move( pkt.bytes ) );
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_AUTH::open() {
    
}