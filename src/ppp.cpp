#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;
extern PPPOEQ ppp_outcoming;

std::string ppp::processPPP( std::vector<uint8_t> &inPkt, const encapsulation_t &encap ) {
    PPPOESESSION_HDR *pppoe = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.data() );

    // Determine this session
    uint16_t sessionId = bswap16( pppoe->session_id );
    pppoe_key_t key{ encap.source_mac, sessionId, encap.outer_vlan, encap.inner_vlan };
    runtime->logger->logDebug() << LOGS::PPP << "Looking up for session: " << key << std::endl;

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

    runtime->logger->logDebug() << LOGS::PPP << "proto " << static_cast<PPP_PROTO>( bswap16( pppoe->ppp_protocol ) ) << " for session " << session.session_id << std::endl;

    switch( static_cast<PPP_PROTO>( bswap16( pppoe->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        if( auto const& [ action, err ] = session.lcp.receive( inPkt ); !err.empty() ) {
            runtime->logger->logError() << LOGS::PPP << "Error while processing LCP packet: " << err << std::endl;
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                if( runtime->lcp_conf->authCHAP ) {
                    session.chap.open();
                } else {
                    session.auth.open();
                }
            } else if( action == PPP_FSM_ACTION::LAYER_DOWN ) {
                runtime->logger->logError() << LOGS::PPP << "LCP goes down, terminate session..." << std::endl;
                if( auto const &err = runtime->deallocateSession( session.session_id ); !err.empty() ) {
                    return "Cannot terminate session: " + err;
                }
            }
        }
        break;
    case PPP_PROTO::PAP:
        if( auto const& [ action, err ] = session.auth.receive( inPkt ); !err.empty() ) {
            runtime->logger->logDebug() << LOGS::PPP << "Error while processing LCP packet: " << err << std::endl;
        }
        break;
    case PPP_PROTO::CHAP:
        if( auto const& [ action, err ] = session.chap.receive( inPkt ); !err.empty() ) {
            runtime->logger->logDebug() << LOGS::PPP << "Error while processing LCP packet: " << err << std::endl;
        }
        break;
    case PPP_PROTO::IPCP:
        if( auto const &[ action, err ] = session.ipcp.receive( inPkt ); !err.empty() ) {
            runtime->logger->logError() << LOGS::PPP << "Error while processing IPCP pkt: " << err << std::endl;
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                runtime->logger->logInfo() << LOGS::PPP << "IPCP is opened: configuring vpp" << std::endl;
                if( auto const &err = session.provision_dp(); !err.empty() ) {
                    runtime->logger->logError() << LOGS::PPP << "Cannot get ip config for session: " << err << std::endl;
                }
                // session.timer.async_wait( std::bind( &PPPOESession::sendEchoReq, session.shared_from_this(), std::placeholders::_1 ) );
            }
        }
        break;
    default:
        runtime->logger->logError() << LOGS::PPP << "Unknown PPP proto: rejecting by default" << std::endl;
        lcp->code = LCP_CODE::CODE_REJ;

        auto header = session.encap.generate_header( runtime->hwaddr, ETH_PPPOE_SESSION );
        inPkt.insert( inPkt.begin(), header.begin(), header.end() );

        // Send this CONF REQ
        ppp_outcoming.push( std::move( inPkt ) );
    }

    return "";
}
