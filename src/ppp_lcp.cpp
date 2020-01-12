#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

std::string LCP_FSM::send_conf_req() {
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

    // Fill LCP part
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );
    pkt.lcp->code = LCP_CODE::CONF_REQ;
    pkt.lcp->identifier = pkt_id;
    // Fill LCP options
    auto lcpOpts = 0;
    auto mru = reinterpret_cast<LCP_OPT_2B*>( pkt.lcp->getPayload() );
    mru->set( LCP_OPTIONS::MRU, runtime->lcp_conf->MRU );
    lcpOpts += mru->len;

    auto auth = reinterpret_cast<LCP_OPT_2B*>( mru->getPayload() );
    uint16_t auth_proto;
    if( runtime->lcp_conf->authCHAP ) {
        auth_proto = static_cast<uint16_t>( PPP_PROTO::CHAP );
    } else if( runtime->lcp_conf->authPAP ) {
        auth_proto = static_cast<uint16_t>( PPP_PROTO::PAP );
    } else {
        return "No Auth proto is chosen!";
    }
    auth->set( LCP_OPTIONS::AUTH_PROTO, auth_proto );
    lcpOpts += auth->len;

    if( session.our_magic_number == 0U ) {
        session.our_magic_number = random_uin32_t();
    }

    auto mn = reinterpret_cast<LCP_OPT_4B*>( auth->getPayload() );
    mn->set( LCP_OPTIONS::MAGIC_NUMBER, session.our_magic_number );
    lcpOpts += mn->len;

    // After all fix lenght in headers
    pkt.lcp->length = htons( sizeof( PPP_LCP ) + lcpOpts );
    pkt.pppoe_session->length = htons( sizeof( PPP_LCP ) + lcpOpts + 2 ); // plus 2 bytes of ppp proto
    pkt.bytes.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) + lcpOpts  );
    printHex( pkt.bytes );

    // Send this CONF REQ
    ppp_outcoming.push( pkt.bytes );

    return "";
}

std::string LCP_FSM::send_conf_ack( Packet pkt ) {
    log( "send_conf_ack current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return "Cannot send conf req for unexisting session";
    }
    auto &session = sessIt->second;

    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;

    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );

    // Fill LCP part
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );
    pkt.lcp->code = LCP_CODE::CONF_ACK;

    // Send this CONF REQ
    ppp_outcoming.push( std::move( pkt.bytes ) );

    return "";
}

std::string LCP_FSM::send_conf_nak( Packet pkt ) {
    log( "send_conf_nak current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return "Cannot send conf req for unexisting session";
    }
    auto &session = sessIt->second;

    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;

    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );

    // Fill LCP part
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );
    pkt.lcp->code = LCP_CODE::CONF_NAK;

    // Send this CONF REQ
    ppp_outcoming.push( std::move( pkt.bytes ) );

    return "";
}

std::string LCP_FSM::check_conf( Packet pkt ) {
    uint32_t len = ntohs( pkt.lcp->length ) - sizeof( PPP_LCP );
    if( len <= 0 ) {
        return "There is no options";
    }

    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return "Cannot send conf req for unexisting session";
    }
    auto &session = sessIt->second;

    LCP_CODE code = LCP_CODE::CONF_ACK;
    uint32_t offset = 0;
    while( len > offset ) {
        auto opt = reinterpret_cast<LCP_OPT_HDR*>( pkt.lcp->getPayload() + offset );
        offset += opt->len;
        if( opt->opt == LCP_OPTIONS::MRU ) {
            auto mru = reinterpret_cast<LCP_OPT_2B*>( opt );
            session.peer_MRU = ntohs( mru->val );
        } else if( opt->opt == LCP_OPTIONS::MAGIC_NUMBER ) {
            auto mn = reinterpret_cast<LCP_OPT_4B*>( opt );
            session.peer_magic_number = ntohl( mn->val );
        } else {
            code = LCP_CODE::CONF_NAK;
        }
    }

    //send pkt
    if( code == LCP_CODE::CONF_ACK ) {
        if( state == PPP_FSM_STATE::Ack_Rcvd ) {
            state = PPP_FSM_STATE::Opened;
            layer_up();
        } else {
            state = PPP_FSM_STATE::Ack_Sent;
        }
        nak_counter = 0;
        return send_conf_ack( pkt );
    } else {
        if( state != PPP_FSM_STATE::Ack_Rcvd ) {
            state = PPP_FSM_STATE::Req_Sent;
        }
        if( code == LCP_CODE::CONF_NAK ) {
            nak_counter++;
        }
        return send_conf_nak( pkt );
    }
}

void LCP_FSM::send_conf_rej() {

}

void LCP_FSM::send_code_rej() {

}

void LCP_FSM::send_term_req() {

}

void LCP_FSM::send_term_ack() {

}