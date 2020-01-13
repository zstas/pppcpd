#include "main.hpp"

void PPP_AUTH::receive( Packet pkt ) {
    pkt.auth = reinterpret_cast<PPP_AUTH_HDR*>( pkt.pppoe_session->getPayload() );
    switch( pkt.auth->code ) {
    case PAP_CODE::AUTHENTICATE_REQ:
        recv_auth_req( pkt );
        break;
    default:
        break;
    }
}

void PPP_AUTH::recv_auth_req( Packet pkt ) {
    uint8_t user_len = *( pkt.auth->getPayload() );
    log( "recv_auth_req user_len: " + std::to_string( user_len ) );
    std::string username { reinterpret_cast<char*>( pkt.auth->getPayload() + 1 ), user_len };
    uint8_t pass_len = *( pkt.auth->getPayload() + user_len + 1 );
    log( "recv_auth_req pass_len: " + std::to_string( pass_len ) );
    std::string password { reinterpret_cast<char*>( pkt.auth->getPayload() + 1 + user_len + 1 ), pass_len };
    log( "recv_auth_req - user: "s + username + " pass: " + password  );
}

void PPP_AUTH::send_auth_ack() {

}

void PPP_AUTH::send_auth_nak() {

}

