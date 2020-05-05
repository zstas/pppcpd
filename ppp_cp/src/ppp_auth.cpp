#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

FSM_RET PPP_AUTH::receive( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->getPayload() );
    switch( auth->code ) {
    case PAP_CODE::AUTHENTICATE_REQ:
        return recv_auth_req( inPkt );
        break;
    default:
        break;
    }
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET PPP_AUTH::recv_auth_req( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->getPayload() );

    uint8_t user_len = *( auth->getPayload() );
    std::string username { reinterpret_cast<char*>( auth->getPayload() + 1 ), reinterpret_cast<char*>( auth->getPayload() + 1 + user_len ) };
    uint8_t pass_len = *( auth->getPayload() + user_len + 1 );
    std::string password { reinterpret_cast<char*>( auth->getPayload() + 1 + user_len + 1 ), reinterpret_cast<char*>( auth->getPayload() + 1 + user_len + 1 + pass_len ) };

    session.username = username;

    if( auto const &[ sid, err ] = runtime->aaa->startSession( username, password ); err.empty() ) {
        session.aaa_session_id = sid;
        return send_auth_ack( inPkt );
    } else {
        return send_auth_nak( inPkt );
    }
}

FSM_RET PPP_AUTH::send_auth_ack( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->getPayload() );

    auth->code = PAP_CODE::AUTHENTICATE_ACK;

    // append empty tag with message
    *auth->getPayload() = 0;
    auth->length = bswap16( sizeof( PPP_AUTH_HDR) + 1 );
    pppoe->length = bswap16( sizeof( PPP_AUTH_HDR) + 3 );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    ppp_outcoming.push( std::move( inPkt ) );
    return { PPP_FSM_ACTION::LAYER_UP, "" };
}

FSM_RET PPP_AUTH::send_auth_nak( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->getPayload() );

    auth->code = PAP_CODE::AUTHENTICATE_NAK;

    // append empty tag with message
    *auth->getPayload() = 0;
    auth->length = bswap16( sizeof( PPP_AUTH_HDR) + 1 );
    pppoe->length = bswap16( sizeof( PPP_AUTH_HDR) + 3 );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    ppp_outcoming.push( std::move( inPkt ) );
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_AUTH::open() {
    
}