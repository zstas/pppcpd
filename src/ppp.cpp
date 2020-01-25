#include "main.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

std::string ppp::processPPP( Packet inPkt ) {
    inPkt.eth = reinterpret_cast<ETHERNET_HDR*>( inPkt.bytes.data() );
    //log( "Ethernet packet:\n" + ether::to_string( inPkt.eth ) );
    if( inPkt.eth->ethertype != ntohs( ETH_PPPOE_SESSION ) ) {
        return "Not pppoe session packet";
    }

    inPkt.pppoe_session = reinterpret_cast<PPPOESESSION_HDR*>( inPkt.eth->getPayload() );

    // Determine this session
    std::array<uint8_t,8> key;
    std::memcpy( key.data(), inPkt.eth->src_mac.data(), 6 );
    uint16_t sessionId = ntohs( inPkt.pppoe_session->session_id );
    *reinterpret_cast<uint16_t*>( &key[ 6 ] ) = sessionId;

    auto const &sessionIt = runtime->sessions.find( sessionId );
    if( sessionIt == runtime->sessions.end() ) {
        return "Cannot find this session in runtime";
    }
    auto &session = sessionIt->second;
    if( !session.started ) {
        session.lcp.open();
        session.lcp.layer_up();
        session.started = true;
    }

    inPkt.lcp = reinterpret_cast<PPP_LCP*>( inPkt.pppoe_session->getPayload() );

    switch( static_cast<PPP_PROTO>( ntohs( inPkt.pppoe_session->ppp_protocol ) ) ) {
    case PPP_PROTO::LCP:
        log( "proto LCP for session " + std::to_string( session.session_id ) );
        if( auto const& [ action, err ] = session.lcp.receive( inPkt ); !err.empty() ) {
            log( "Error while processing LCP packet: " + err );
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                session.auth.open();
            } else if( action == PPP_FSM_ACTION::LAYER_DOWN ) {
                //session.auth.close();
            }
        }
        break;
    case PPP_PROTO::PAP:
        log( "proto PAP" );
        if( auto const& [ action, err ] = session.auth.receive( inPkt ); !err.empty() ) {
            log( "Error while processing LCP packet: " + err );
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                session.ipcp.open();
                session.ipcp.layer_up();
            } else if( action == PPP_FSM_ACTION::LAYER_DOWN ) {
                //session.ipcp.close();
            }
        }
        break;
    case PPP_PROTO::IPCP:
        log( "proto IPCP" );
        if( auto const &[ action, err ] = session.ipcp.receive( inPkt ); !err.empty() ) {
            log( "Error while processing IPCP pkt: " + err );
        } else {
            if( action == PPP_FSM_ACTION::LAYER_UP ) {
                log( "IPCP is opened: configuring vpp" );
                if( auto const &[ conf, err ] = runtime->aaa->getConf( session.username ); err.empty() ) {
                    if( !runtime->vpp->add_pppoe_session( conf.address, session.session_id, session.mac ) ) {
                        log( "Cannot add new session to vpp " );
                    }
                } else {
                    log("Cannot get ip config for session: " + err );
                }
            }
        }
        break;
    default:
        log( "unknown proto" );
    }

    return "";
}
