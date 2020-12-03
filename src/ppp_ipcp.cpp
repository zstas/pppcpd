#include <vector>
#include <string>
#include <iostream>

#include "ppp_ipcp.hpp"
#include "packet.hpp"
#include "runtime.hpp"
#include "string_helpers.hpp"
#include "aaa_session.hpp"

using namespace std::string_literals;

extern std::shared_ptr<PPPOERuntime> runtime;

IPCP_FSM::IPCP_FSM( PPPOESession &s ):
	session( s ),
    PPP_FSM( s.session_id )
{}

FSM_RET IPCP_FSM::send_conf_req() {
    runtime->logger->logDebug() << LOGS::IPCP << "send_conf_req current state: " << state << std::endl;
    std::vector<uint8_t> pkt;
    pkt.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + 256 );

    // Fill pppoe part
    PPPOESESSION_HDR* pppoe = reinterpret_cast<PPPOESESSION_HDR*>( pkt.data() );
    pppoe->version = 1;
    pppoe->type = 1;
    pppoe->ppp_protocol = bswap( static_cast<uint16_t>( PPP_PROTO::IPCP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    pppoe->session_id = bswap( session_id );

    // Fill IPCP part; here we just can use lcp header
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_REQ;
    lcp->identifier = pkt_id;
    // Fill LCP options
    auto ipcpOpts = 0;
    auto ipad = reinterpret_cast<IPCP_OPT_4B*>( lcp->getPayload() );
    ipad->set( IPCP_OPTIONS::IP_ADDRESS, 0x64400001 );
    ipcpOpts += ipad->len;

    // After all fix lenght in headers
    lcp->length = htons( sizeof( PPP_LCP ) + ipcpOpts );
    pppoe->length = htons( sizeof( PPP_LCP ) + ipcpOpts + 2 ); // plus 2 bytes of ppp proto
    pkt.resize( sizeof( ETHERNET_HDR) + sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) + ipcpOpts  );

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    pkt.insert( pkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    runtime->ppp_outcoming.push( pkt );

    return { PPP_FSM_ACTION::NONE, "" };
}


FSM_RET IPCP_FSM::send_conf_ack( std::vector<uint8_t> &inPkt ) {
    runtime->logger->logDebug() << LOGS::IPCP << "send_conf_ack current state: " << state << std::endl;

    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_ACK;

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    runtime->ppp_outcoming.push( std::move( inPkt ) );

    if( state == PPP_FSM_STATE::Opened ) {
        return { PPP_FSM_ACTION::LAYER_UP, "" };
    }

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_conf_nak( std::vector<uint8_t> &inPkt ) {
    runtime->logger->logDebug() << LOGS::IPCP << "send_conf_nak current state: " << state << std::endl;
    auto const &[ aaa_session, err ] = runtime->aaa->getSession( session.aaa_session_id );
    if( !err.empty() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf nak cause: "s + err };
    }

    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_NAK;

    // Set our parameters
    auto opts = lcp->parseIPCPOptions();
    for( auto &opt: opts ) {
        switch( opt->opt ) {
        case IPCP_OPTIONS::IP_ADDRESS: {
            auto ipad = reinterpret_cast<IPCP_OPT_4B*>( opt );
            ipad->val = htonl( aaa_session->address.to_uint() );
            break;
        }
        case IPCP_OPTIONS::PRIMARY_DNS: {
            auto dns1 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            dns1->val = htonl( aaa_session->dns1.to_uint() );
            break;
        }
        case IPCP_OPTIONS::SECONDARY_DNS: {
            auto dns2 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            dns2->val = htonl( aaa_session->dns2.to_uint() );
            break;
        }
        default:
            break;
        }
    }

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    inPkt.insert( inPkt.begin(), header.begin(), header.end() );

    // Send this CONF REQ
    runtime->ppp_outcoming.push( std::move( inPkt ) );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::check_conf( std::vector<uint8_t> &inPkt ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );

    uint32_t len = bswap( lcp->length ) - sizeof( PPP_LCP );
    if( len <= 0 ) {
        return { PPP_FSM_ACTION::NONE, "There is no options" };
    }

    auto const &[ aaa_session, err ] = runtime->aaa->getSession( session.aaa_session_id );
    if( !err.empty() ) {
        return { PPP_FSM_ACTION::NONE, "Cannot send conf nak cause: "s + err };
    } else {
        session.address = aaa_session->address.to_uint();
        session.vrf = aaa_session->vrf;
        session.unnumbered = aaa_session->unnumbered;
    }

    LCP_CODE code = LCP_CODE::CONF_ACK;

    // Check options
    auto opts = lcp->parseIPCPOptions();
    std::vector<uint8_t> rejected_options;
    for( auto const &opt: opts ) {
        if( opt->opt == IPCP_OPTIONS::IP_ADDRESS ||
            opt->opt == IPCP_OPTIONS::PRIMARY_DNS ||
            opt->opt == IPCP_OPTIONS::SECONDARY_DNS ) {
            continue;
        }
        rejected_options.insert( rejected_options.end(), (uint8_t*)opt, (uint8_t*)opt + opt->len );
    }

    if( !rejected_options.empty() ) {
        return send_conf_rej( rejected_options, lcp->identifier );
    }

    for( auto &opt: opts ) {
        switch( opt->opt ) {
        case IPCP_OPTIONS::IP_ADDRESS: {
            auto ipad = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( ipad->val != htonl( aaa_session->address.to_uint() ) ) {
                code = LCP_CODE::CONF_NAK;
            }
            break;
        }
        case IPCP_OPTIONS::PRIMARY_DNS: {
            auto dns1 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( dns1->val != htonl( aaa_session->dns1.to_uint() ) ) {
                code = LCP_CODE::CONF_NAK;
            }
            break;
        }
        case IPCP_OPTIONS::SECONDARY_DNS: {
            auto dns2 = reinterpret_cast<IPCP_OPT_4B*>( opt );
            if( dns2->val != htonl( aaa_session->dns2.to_uint() ) ) {
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

FSM_RET IPCP_FSM::send_conf_rej( std::vector<uint8_t> &rejected_options, uint8_t pkt_id ) {
    runtime->logger->logDebug() << LOGS::LCP << "send_conf_rej current state: " << state << std::endl;

    std::vector<uint8_t> pkt;
    pkt.resize( sizeof( PPPOESESSION_HDR ) + sizeof( PPP_LCP ) );

    // Fill pppoe part
    PPPOESESSION_HDR* pppoe = reinterpret_cast<PPPOESESSION_HDR*>( pkt.data() );
    pppoe->version = 1;
    pppoe->type = 1;
    pppoe->ppp_protocol = bswap( static_cast<uint16_t>( PPP_PROTO::IPCP ) );
    pppoe->code = PPPOE_CODE::SESSION_DATA;
    pppoe->session_id = bswap( session_id );

    // Fill LCP part
    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    lcp->code = LCP_CODE::CONF_REJ;
    lcp->identifier = pkt_id;
    lcp->length = bswap( (uint16_t)( sizeof( PPP_LCP ) + rejected_options.size() ) );

    // Insert rejected options
    pkt.insert( pkt.end(), rejected_options.begin(), rejected_options.end() );

    // After all fix lenght in headers
    pppoe = reinterpret_cast<PPPOESESSION_HDR*>( pkt.data() );
    lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );
    pppoe->length = bswap( (uint16_t)( sizeof( PPP_LCP ) + rejected_options.size() + 2 ) ); // plus 2 bytes of ppp proto

    auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
    pkt.insert( pkt.begin(), header.begin(), header.end() );

    // Send this CONF REJ
    runtime->ppp_outcoming.push( std::move( pkt ) );

    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_code_rej() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_term_req() {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_term_ack( std::vector<uint8_t> &inPkt ) {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::send_echo_rep( std::vector<uint8_t> &inPkt ) {
    return { PPP_FSM_ACTION::NONE, "" };
}

FSM_RET IPCP_FSM::recv_echo_rep( std::vector<uint8_t> &inPkt ) {
    return { PPP_FSM_ACTION::NONE, "" };
}