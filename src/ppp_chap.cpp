#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

FSM_RET PPP_CHAP::receive( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_CHAP_HDR *auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );
    switch( auth->code ) {
    case CHAP_CODE::RESPONSE:
        recv_auth_req( inPkt );
        break;
    default:
        break;
    }
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_CHAP::recv_auth_req( std::vector<uint8_t> &inPkt ) {
    if( started ) {
        send_auth_ack();
        return;
    }
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_CHAP_HDR *auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );

    uint8_t user_len = *( auth->getPayload() );
    std::string username { reinterpret_cast<char*>( auth->getPayload() + 1 ), reinterpret_cast<char*>( auth->getPayload() + 1 + user_len ) };
    std::string response { auth->value.begin(), auth->value.end() };

    session.username = username;

    runtime->aaa->startSessionCHAP( username, challenge, response, session, std::bind( &PPP_CHAP::auth_callback, this, std::placeholders::_1, std::placeholders::_2 ) );
}

FSM_RET PPP_CHAP::auth_callback( uint32_t sid, const std::string &err ) {
    if( err.empty() ) {
        session.aaa_session_id = sid;
        started = true;
        return send_auth_ack();
    } else {
        return send_auth_nak();
    }
}

FSM_RET PPP_CHAP::send_auth_ack() {
    std::vector<uint8_t> inPkt;
    inPkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_CHAP_HDR ) );
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_CHAP_HDR *auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );

    pppoe->type = 1;
    pppoe->version = 1;
    pppoe->session_id = bswap16( session.session_id );
    pppoe->ppp_protocol = bswap16( static_cast<uint16_t>( PPP_PROTO::CHAP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    auth->code = CHAP_CODE::SUCCESS;

    // append empty tag with message
    *auth->getPayload() = 0;
    auth->length = bswap16( sizeof( PPP_CHAP_HDR) );
    pppoe->length = bswap16( sizeof( PPP_CHAP_HDR) + 2 );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    ppp_outcoming.push( std::move( inPkt ) );

    session.ipcp.open();
    session.ipcp.layer_up();
    
    return { PPP_FSM_ACTION::LAYER_UP, "" };
}

FSM_RET PPP_CHAP::send_auth_nak() {
    std::vector<uint8_t> inPkt;
    inPkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_CHAP_HDR ) );
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_CHAP_HDR *auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );

    pppoe->type = 1;
    pppoe->version = 1;
    pppoe->session_id = bswap16( session.session_id );;
    pppoe->ppp_protocol = bswap16( static_cast<uint16_t>( PPP_PROTO::CHAP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    auth->code = CHAP_CODE::FAILURE;

    // append empty tag with message
    *auth->getPayload() = 0;
    auth->length = bswap16( sizeof( PPP_CHAP_HDR) );
    pppoe->length = bswap16( sizeof( PPP_CHAP_HDR) + 2 );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    ppp_outcoming.push( std::move( inPkt ) );
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET PPP_CHAP::send_conf_req() {
    runtime->logger->logInfo() << LOGS::PPP << "Sending CHAP conf-req" << std::endl;
    std::vector<uint8_t> inPkt;
    inPkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_CHAP_HDR ) );
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_CHAP_HDR *auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );

    auto const &pol_it = runtime->conf.pppoe_confs.find( session.encap.outer_vlan );
    const PPPOEPolicy &pppoe_conf = ( pol_it == runtime->conf.pppoe_confs.end() ) ? runtime->conf.default_pppoe_conf : pol_it->second;

    pppoe->type = 1;
    pppoe->version = 1;
    pppoe->session_id = bswap16( session.session_id );;
    pppoe->ppp_protocol = bswap16( static_cast<uint16_t>( PPP_PROTO::CHAP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    auth->code = CHAP_CODE::CHALLENGE;
    challenge = md5( random_string( 32 ) );
    challenge.resize( sizeof( auth->value ) );
    std::copy( challenge.begin(), challenge.end(), auth->value.begin() );
    auth->value_len = sizeof( auth->value );
    inPkt.insert( inPkt.end(), pppoe_conf.ac_name.begin(), pppoe_conf.ac_name.end() );

    pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    auth = reinterpret_cast<PPP_CHAP_HDR*>( pppoe->getPayload() );

    auth->length = bswap16( sizeof( PPP_CHAP_HDR ) + pppoe_conf.ac_name.size() );
    pppoe->length = bswap16( sizeof( PPP_CHAP_HDR ) + pppoe_conf.ac_name.size() + 2 );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this packet
    ppp_outcoming.push( std::move( inPkt ) );
    return { PPP_FSM_ACTION::NONE, "" };
}

void PPP_CHAP::open() {
    runtime->logger->logInfo() << LOGS::PPP << "CHAP opened" << std::endl;
    send_conf_req();
}