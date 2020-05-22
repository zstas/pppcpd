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
    io_service io;
    runtime = std::make_shared<PPPOERuntime>( "pppoe-cp" );

    // At this point all the config lies here
    runtime->pppoe_conf = std::make_shared<PPPOEPolicy>();
    runtime->pppoe_conf->ac_name = "vBNG AC PPPoE";
    runtime->pppoe_conf->insertCookie = true;
    runtime->pppoe_conf->ignoreServiceName = true;

    // LCP options
    runtime->lcp_conf = std::make_shared<LCPPolicy>();

    //runtime->aaa = std::make_shared<AAA>( 0x6440000A, 0x644000FE, 0x08080808, 0x01010101 );
    RadiusDict dict { "/usr/share/freeradius/dictionary.rfc2865" };
    runtime->aaa = std::make_shared<AAA>( io, address_v4::from_string( "127.0.0.1" ), 1812, "testing123", dict );
    runtime->vpp = std::make_shared<VPPAPI>();

    EVLoop loop( io );

    while( !interrupted ) {
        io.run();
    }

    return 0;
}
