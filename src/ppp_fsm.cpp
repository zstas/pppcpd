#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

void PPP_FSM::receive( Packet pkt ) {
    log( "receive pkt in state: " + std::to_string( state ) );
    if( pkt.lcp == nullptr ) {
        return;
    }

    if( state == PPP_FSM_STATE::Initial || 
        state == PPP_FSM_STATE::Starting ) {
            log( "Received packet in invalid state: "s + std::to_string( state ) );
            return;
    }
    
    switch( pkt.lcp->code ) {
    case LCP_CODE::CONF_REQ:
        if( auto const &err = recv_conf_req( std::move( pkt ) ); !err.empty() ) {
            log( "Error while receiving LCP packet CONF_REQ: " + err );
        }
        break;
    case LCP_CODE::CONF_ACK:
        if( auto const &err = recv_conf_ack( std::move( pkt ) ); !err.empty() ) {
            log( "Error while receiving LCP packet CONF_ACK: " + err );
        }
	    break;
    
    case LCP_CODE::CONF_NAK:
    case LCP_CODE::CONF_REJ:
	    //fsm_rconfnakrej(f, code, id, inp, len);
	    break;
    
    case LCP_CODE::TERM_REQ:
	    //fsm_rtermreq(f, id, inp, len);
	    break;
    
    case LCP_CODE::TERM_ACK:
	    //fsm_rtermack(f);
	    break; 
    
    case LCP_CODE::CODE_REJ:
        //fsm_rcoderej
        break;
    default:
        //send CODEREJ
        break;
    }
    log( "FSM state: " + std::to_string( state ) );
}

std::string PPP_FSM::recv_conf_req( Packet pkt ) {
    log( "recv_conf_req current state: " + std::to_string( state ) );
    switch( state ){
    case PPP_FSM_STATE::Closing:
    case PPP_FSM_STATE::Stopping:
        return "We're stopping or closing right now";
    case PPP_FSM_STATE::Closed:
        // send TERM ACK
        return "Receive conf req in closed state";
    case PPP_FSM_STATE::Opened:
        // Restart connection
        layer_down();
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    case PPP_FSM_STATE::Stopped:
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    default:
        break;
    }

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

    return "";
}

std::string PPP_FSM::send_conf_req() {
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

void PPP_FSM::layer_up() {
    switch( state ) {
    case PPP_FSM_STATE::Initial:
	    state = PPP_FSM_STATE::Closed;
	    break;

    case PPP_FSM_STATE::Starting:
	    if( auto err = send_conf_req(); !err.empty() ) {
            log( "Cannot set layer up: " + err );
        } else {
	        state = PPP_FSM_STATE::Req_Sent;
        }
	    break;

    default:
        break;
    }
}

void PPP_FSM::layer_down() {
    return;
}

void PPP_FSM::open() {
    switch( state ) {
    case PPP_FSM_STATE::Initial:
        state = PPP_FSM_STATE::Starting;
        //starting()
        break;
    case PPP_FSM_STATE::Closed:
        if( auto err = send_conf_req(); !err.empty() ) {
            log( "Cannot set layer up: " + err );
        } else {
	        state = PPP_FSM_STATE::Req_Sent;
        }
        break;
    case PPP_FSM_STATE::Closing:
        state = PPP_FSM_STATE::Stopping;
    case PPP_FSM_STATE::Stopped:
    case PPP_FSM_STATE::Opened:
        // If restart
        break;
    default:
        break;
    }
}

std::string PPP_FSM::send_conf_ack( Packet pkt ) {
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

std::string PPP_FSM::send_conf_nak( Packet pkt ) {
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

std::string PPP_FSM::recv_conf_ack( Packet pkt ) {
    log( "recv_conf_ack current state: " + std::to_string( state ) );

    // Parse in case of moved data
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );

    if( pkt.lcp->identifier != pkt_id ) {
        return "Packet identifier is not match with our";
    }

    seen_ack = true;

    switch( state ) {
    case PPP_FSM_STATE::Closed:
    case PPP_FSM_STATE::Stopped:
        // send TERM ACK
        break;
    case PPP_FSM_STATE::Req_Sent:
        state = PPP_FSM_STATE::Ack_Rcvd;
        break;
    case PPP_FSM_STATE::Ack_Rcvd:
        log( "extra ack, but not considering it is like a problem" );
        break;
    case PPP_FSM_STATE::Ack_Sent:
        state = PPP_FSM_STATE::Opened;
        break;
    case PPP_FSM_STATE::Opened:
        // Restarting the connection
        send_conf_req();
        state = PPP_FSM_STATE::Req_Sent;
        break;
    default:
        log( "Incorrect state?" );
        break;
    }

    return "";
}