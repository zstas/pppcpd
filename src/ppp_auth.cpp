#include <tuple>
#include <memory>
#include <vector>

#include "ppp_fsm.hpp"
#include "evloop.hpp"
#include "ppp_auth.hpp"
#include "runtime.hpp"
#include "packet.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

FSM_RET PPP_AUTH::receive( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->data );
    switch( auth->code ) {
    case PAP_CODE::AUTHENTICATE_REQ:
        recv_auth_req( inPkt );
        break;
    default:
        break;
    }
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_AUTH::recv_auth_req( std::vector<uint8_t> &inPkt ) {
    if( started ) {
        send_auth_ack();
        return;
    }
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->data );

    uint8_t user_len = *( auth->data );
    std::string username { reinterpret_cast<char*>( auth->data + 1 ), reinterpret_cast<char*>( auth->data + 1 + user_len ) };
    uint8_t pass_len = *( auth->data + user_len + 1 );
    std::string password { reinterpret_cast<char*>( auth->data + 1 + user_len + 1 ), reinterpret_cast<char*>( auth->data + 1 + user_len + 1 + pass_len ) };

    session.username = username;

    runtime->aaa->startSession( username, password, session, std::bind( &PPP_AUTH::auth_callback, this, std::placeholders::_1, std::placeholders::_2 ) );
}

FSM_RET PPP_AUTH::auth_callback( uint32_t sid, const std::string &err ) {
    if( err.empty() ) {
        session.aaa_session_id = sid;
        started = true;
        return send_auth_ack();
    } else {
        return send_auth_nak();
    }
}

FSM_RET PPP_AUTH::send_auth_ack() {
    std::vector<uint8_t> inPkt;
    inPkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_AUTH_HDR ) );
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->data );

    pppoe->type = 1;
    pppoe->version = 1;
    pppoe->session_id = bswap( session.session_id );
    pppoe->ppp_protocol = bswap( static_cast<uint16_t>( PPP_PROTO::PAP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    auth->code = PAP_CODE::AUTHENTICATE_ACK;

    // append empty tag with message
    *auth->data = 0;
    auth->length = bswap( (uint16_t)sizeof( PPP_AUTH_HDR) );
    pppoe->length = bswap( (uint16_t)( sizeof( PPP_AUTH_HDR) + 2 ) );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    runtime->ppp_outcoming.push( std::move( inPkt ) );

    session.ipcp.open();
    session.ipcp.layer_up();
    
    return { PPP_FSM_ACTION::LAYER_UP, "" };
}

FSM_RET PPP_AUTH::send_auth_nak() {
    std::vector<uint8_t> inPkt;
    inPkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_AUTH_HDR ) );
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_AUTH_HDR *auth = reinterpret_cast<PPP_AUTH_HDR*>( pppoe->data );

    pppoe->type = 1;
    pppoe->version = 1;
    pppoe->session_id = bswap( session.session_id );;
    pppoe->ppp_protocol = bswap( static_cast<uint16_t>( PPP_PROTO::PAP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    auth->code = PAP_CODE::AUTHENTICATE_NAK;

    // append empty tag with message
    *auth->data = 0;
    auth->length = bswap( (uint16_t)sizeof( PPP_AUTH_HDR) );
    pppoe->length = bswap( (uint16_t)( sizeof( PPP_AUTH_HDR) + 2 ) );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    runtime->ppp_outcoming.push( std::move( inPkt ) );
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_AUTH::open() {
    
}