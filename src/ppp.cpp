#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

std::string ppp::processPPP( std::vector<uint8_t> &inPkt, const encapsulation_t &encap ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Determine this session
    uint16_t sessionId = bswap16( pppoe->session_id );
    pppoe_key_t key{ encap.source_mac, sessionId, encap.outer_vlan, encap.inner_vlan };
    runtime->logger->logDebug() << "Looking up for session: " << key;

    auto const &sessionIt = runtime->activeSessions.find( key );
    if( sessionIt == runtime->activeSessions.end() ) {
        return "Cannot find this session in runtime";
    }

    auto &session = sessionIt->second;
    if( !session.started ) {
        session.lcp.open();
        session.lcp.layer_up();
        session.started = true;
    }

    PPP_LCP *lcp = reinterpret_cast<PPP_LCP*>( pppoe->getPayload() );

    runtime->logger->logDebug() << "proto " << static_cast<PPP_PROTO>( bswap16( pppoe->ppp_protocol ) ) << " for session " << session.session_id;

    switch( static_cast<PPP_PROTO>( bswap16( pppoe->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        if( auto const& [ action, err ] = session.lcp.receive( inPkt ); !err.empty() ) {
            runtime->logger->logError() << "Error while processing LCP packet: " << err;
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                if( runtime->lcp_conf->authCHAP ) {
                    session.chap.open();
                } else {
                    session.auth.open();
                }
            } else if( action == PPP_FSM_ACTION::LAYER_DOWN ) {
                runtime->logger->logError() << "LCP goes down, terminate session...";
                if( auto const &err = runtime->deallocateSession( session.session_id ); !err.empty() ) {
                    return "Cannot terminate session: " + err;
                }
            }
        }
        break;
    case PPP_PROTO::PAP:
        if( auto const& [ action, err ] = session.auth.receive( inPkt ); !err.empty() ) {
            runtime->logger->logDebug() << "Error while processing LCP packet: " << err;
        }
        break;
    case PPP_PROTO::CHAP:
        if( auto const& [ action, err ] = session.chap.receive( inPkt ); !err.empty() ) {
            runtime->logger->logDebug() << "Error while processing LCP packet: " << err;
        }
        break;
    case PPP_PROTO::IPCP:
        if( auto const &[ action, err ] = session.ipcp.receive( inPkt ); !err.empty() ) {
            runtime->logger->logError() << "Error while processing IPCP pkt: " << err;
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                runtime->logger->logInfo() << "IPCP is opened: configuring vpp";
                if( auto const &err = session.provision_dp(); !err.empty() ) {
                    runtime->logger->logError() << "Cannot get ip config for session: " << err;
                }
                // session.timer.async_wait( std::bind( &PPPOESession::sendEchoReq, session.shared_from_this(), std::placeholders::_1 ) );
            }
        }
        break;
    default:
        runtime->logger->logDebug() << "Unknown PPP proto: rejecting by default";
        lcp->code = LCP_CODE::CODE_REJ;

        auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
        inPkt.insert( inPkt.begin(), header.begin(), header.end() );

        // Send this CONF REQ
        ppp_outcoming.push( std::move( inPkt ) );
    }

    return "";
}
