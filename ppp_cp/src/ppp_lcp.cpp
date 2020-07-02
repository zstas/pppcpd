#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

LCP_FSM::LCP_FSM( PPPOESession &s ):
	session( s ),
    PPP_FSM( s.session_id )
{}

FSM_RET LCP_FSM::send_conf_req() {
    log( "LCP: send_conf_req current state: " + std::to_string( state ) );
    std::vector<uint8_t> pkt;
    pkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) + 256 );

    // Fill pppoe part
    PPPOESESSION_HDR* pppoe = reinterpret_cast<PPPOESESSION_HDR*>( pkt.data() );
    pppoe->version = 1;
    pppoe->type = 1;
    pppoe->ppp_protocol = bswap16( static_cast<uint16_t>( PPP_PROTO::LCP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    pppoe->session_id = bswap16( session_id );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_REQ;
    lcp->identifier = pkt_id;

    // Fill LCP options
    auto lcpOpts = 0;
    auto mru = reinterpret_cast<LCP_OPT_2B*>( lcp->getPayload() );
    mru->set( LCP_OPTIONS::MRU, runtime->lcp_conf->MRU );
    lcpOpts += mru->len;

    auto auth = reinterpret_cast<LCP_OPT_2B*>( mru->getPayload() );
    uint16_t auth_proto;
    if( runtime->lcp_conf->authCHAP ) {
        auth_proto = static_cast<uint16_t>( PPP_PROTO::CHAP );
    } else if( runtime->lcp_conf->authPAP ) {
        auth_proto = static_cast<uint16_t>( PPP_PROTO::PAP );
    } else {
        return { PPP_FSM_ACTION::NONE, "No Auth proto is chosen!" };
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
    lcp->length = bswap16( sizeof( PPP_LCP ) + lcpOpts );
    pppoe->length = bswap16( sizeof( PPP_LCP ) + lcpOpts + 2 ); // plus 2 bytes of ppp proto
    pkt.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) + lcpOpts  );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    pkt.insert( pkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    ppp_outcoming.push( pkt );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_conf_ack( std::vector<uint8_t> &inPkt ) {
    log( "LCP: send_conf_ack current state: " + std::to_string( state ) );

    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_ACK;

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    ppp_outcoming.push( std::move( inPkt ) );
    if( state == PPP_FSM_STATE::Opened ) {
        return { PPP_FSM_ACTION::LAYER_UP, "" };
    }

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_conf_nak( std::vector<uint8_t> &inPkt ) {
    log( "LCP: send_conf_nak current state: " + std::to_string( state ) );

    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_NAK;

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    ppp_outcoming.push( std::move( inPkt ) );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::check_conf( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );

    uint32_t len = bswap16( lcp->length ) - sizeof( PPP_LCP );
    if( len <= 0 ) {
        return { PPP_FSM_ACTION::NONE, "There is no options" };
    }

    LCP_CODE code = LCP_CODE::CONF_ACK;
    uint32_t offset = 0;
    while( len > offset ) {
        auto opt = reinterpret_cast<LCP_OPT_HDR*>( lcp->getPayload() + offset );
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
        return send_conf_ack( inPkt );
    } else {
        if( state != PPP_FSM_STATE::Ack_Rcvd ) {
            state = PPP_FSM_STATE::Req_Sent;
        }
        if( code == LCP_CODE::CONF_NAK ) {
            nak_counter++;
        }
        return send_conf_nak( inPkt );
    }
}

FSM_RET LCP_FSM::send_conf_rej() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_code_rej() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_term_req() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_term_ack( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_LCP_ECHO *lcp_echo = reinterpret_cast<PPP_LCP_ECHO*>( pppoe->getPayload() );

    lcp_echo->code = LCP_CODE::TERM_ACK;
    if( lcp_echo->magic_number != bswap32( session.peer_magic_number ) ) {
        return { PPP_FSM_ACTION::NONE, "Magic number is wrong!" };
    }
    lcp_echo->magic_number = bswap32( session.our_magic_number );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    log( "Sending LCP TERM ACK" );
    ppp_outcoming.push( inPkt );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET LCP_FSM::send_echo_rep( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_LCP_ECHO *lcp_echo = reinterpret_cast<PPP_LCP_ECHO*>( pppoe->getPayload() );

    lcp_echo->code = LCP_CODE::ECHO_REPLY;
    if( lcp_echo->magic_number != htonl( session.peer_magic_number ) ) {
        return { PPP_FSM_ACTION::NONE, "Magic number is wrong!" };
    }
    lcp_echo->magic_number = htonl( session.our_magic_number );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    // log( "Sending LCP ECHO REPLY" );
    ppp_outcoming.push( inPkt );

    return { PPP_FSM_ACTION::NONE, "" };
}