#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

FSM_RET IPCP_FSM::send_conf_req() {
    log( "IPCP: send_conf_req current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf req for unexisting session" };
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
    pkt.pppoe_session->ppp_protocol = htons( static_cast<uint16_t>( PPP_PROTO::IPCP ) );
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

    // Send this CONF REQ
    ppp_outcoming.push( pkt.bytes );

    return { PPP_FSM_ACTION::NONE, "" };
}


FSM_RET IPCP_FSM::send_conf_ack( Packet &pkt ) {
    log( "IPCP: send_conf_ack current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf req for unexisting session" };
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

    if( state == PPP_FSM_STATE::Opened ) {
        return { PPP_FSM_ACTION::LAYER_UP, "" };
    }

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_conf_nak( Packet &pkt ) {
    log( "IPCP: send_conf_nak current state: " + std::to_string( state ) );
    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf req for unexisting session" };
    }
    auto &session = sessIt->second;
    auto const &[ conf, err ] = runtime->aaa->getConf( session.username );
    if( !err.empty() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf nak cause: "s + err };
    }

    // Fill ethernet part
    pkt.eth = reinterpret_cast<ETHERNET_HDR*>( pkt.bytes.data() );
    pkt.eth->dst_mac = session.mac;
    pkt.eth->src_mac = runtime->hwaddr;

    pkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( pkt.eth->getPayload() );

    // Fill LCP part
    pkt.lcp = reinterpret_cast<PPP_LCP*>( pkt.pppoe_session->getPayload() );
    pkt.lcp->code = LCP_CODE::CONF_NAK;

    // Set our parameters
    auto opts = pkt.lcp->parseIPCPOptions();
    for( auto &opt: opts ) {
        switch( opt->opt ) {
        case IPCP_OPTIONS::IP_ADDRESS: {
            auto ipad = reinterpret_cast<IPCP_OPT_4B*>( opt );
            ipad->val = conf.address;
            break;
        }
        case IPCP_OPTIONS::PRIMARY_DNS: {
            auto dns1 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            dns1->val = conf.dns1;
            break;
        }
        case IPCP_OPTIONS::SECONDARY_DNS: {
            auto dns2 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            dns2->val = conf.dns2;
            break;
        }
        default:
            break;
        }
    }

    // Send this CONF REQ
    ppp_outcoming.push( std::move( pkt.bytes ) );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::check_conf( Packet &pkt ) {
    uint32_t len = ntohs( pkt.lcp->length ) - sizeof( PPP_LCP );
    if( len <= 0 ) {
        return { PPP_FSM_ACTION::NONE, "There is no options" };
    }

    auto const &sessIt = runtime->sessions.find( session_id );
    if( sessIt == runtime->sessions.end() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf req for unexisting session" };
    }
    auto &session = sessIt->second;
    auto const &[ conf, err ] = runtime->aaa->getConf( session.username );
    if( !err.empty() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf nak cause: "s + err };
    }

    LCP_CODE code = LCP_CODE::CONF_ACK;

    // Check options
    auto opts = pkt.lcp->parseIPCPOptions();
    for( auto &opt: opts ) {
        switch( opt->opt ) {
        case IPCP_OPTIONS::IP_ADDRESS: {
            auto ipad = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( ipad->val != conf.address ) {
                code = LCP_CODE::CONF_NAK;
            }
            break;
        }
        case IPCP_OPTIONS::PRIMARY_DNS: {
            auto dns1 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( dns1->val != conf.dns1 ) {
                code = LCP_CODE::CONF_NAK;
            }
            break;
        }
        case IPCP_OPTIONS::SECONDARY_DNS: {
            auto dns2 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( dns2->val != conf.dns2 ) {
                code = LCP_CODE::CONF_NAK;
            }
            break;
        }
        default:
            break;
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

FSM_RET IPCP_FSM::send_conf_rej() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_code_rej() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_term_req() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_term_ack() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_echo_rep( Packet &pkt ) {
    return { PPP_FSM_ACTION::NONE, "" };
}