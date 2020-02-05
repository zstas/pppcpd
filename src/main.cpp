#include "main.hpp"

// Some global vars
std::shared_ptr<PPPOERuntime> runtime;
std::atomic_bool interrupted { false };

// Queues for packets
PPPOEQ pppoe_incoming;
PPPOEQ pppoe_outcoming;
PPPOEQ ppp_incoming;
PPPOEQ ppp_outcoming;

int main( int argc, char *argv[] ) {
    runtime = std::make_shared<PPPOERuntime>( "pppoe-cp" );

    // At this point all the config lies here
    runtime->pppoe_conf = std::make_shared<PPPOEPolicy>();
    runtime->pppoe_conf->ac_name = "vBNG AC PPPoE";
    runtime->pppoe_conf->insertCookie = true;
    runtime->pppoe_conf->ignoreServiceName = true;

    // LCP options
    runtime->lcp_conf = std::make_shared<LCPPolicy>();

    runtime->aaa = std::make_shared<AAA>( 0x6440000A, 0x644000FE, 0x08080808, 0x01010101 );
    runtime->vpp = std::make_shared<VPPAPI>();

    std::thread pppoe_dispatcher ([]() -> void {
        while( !interrupted ) {
            auto pkt = pppoe_incoming.pop();
            if( auto const &[ reply, error ] = pppoe::processPPPOE( pkt ); !error.empty() ) {
                log( error );
            } else {
                pppoe_outcoming.push( reply );
            }
        }
    });

    std::thread ppp_dispatcher ([]() -> void {
        while( !interrupted ) {
            auto pkt = ppp_incoming.pop();
            if( auto const error = ppp::processPPP( pkt ); !error.empty() ) {
                log( error );
            }
        }
    });

    EVLoop loop;

    pppoe_dispatcher.join();
    ppp_dispatcher.join();

    return 0;
}
