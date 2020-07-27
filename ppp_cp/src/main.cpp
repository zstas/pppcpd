#include "main.hpp"

#include <yaml-cpp/yaml.h>
#include "yaml.hpp"

// Some global vars
std::shared_ptr<PPPOERuntime> runtime;
std::atomic_bool interrupted { false };

// Queues for packets
PPPOEQ pppoe_incoming;
PPPOEQ pppoe_outcoming;
PPPOEQ ppp_incoming;
PPPOEQ ppp_outcoming;

static void conf_init() {
    PPPOEPolicy pppoe_pol;
    pppoe_pol.ac_name = "vBNG AC PPPoE";
    pppoe_pol.insert_cookie = true;
    pppoe_pol.ignore_service_name = true;
    pppoe_pol.service_name = { "inet", "pppoe" };

    PPPOELocalTemplate pppoe_template;
    pppoe_template.framed_pool = "pppoe_pool1";
    pppoe_template.dns1 = address_v4_t::from_string( "8.8.8.8" );
    pppoe_template.dns2 = address_v4_t::from_string( "1.1.1.1" );
    AAAConf aaa_conf;
    aaa_conf.local_template.emplace( std::move( pppoe_template ) );
    aaa_conf.method = { AAA_METHODS::NONE };
    aaa_conf.pools.emplace( std::piecewise_construct,
        std::forward_as_tuple( "pppoe_pool1" ),
        std::forward_as_tuple( "100.64.0.10", "100.64.255.255" ) );
    aaa_conf.pools.emplace( std::piecewise_construct,
        std::forward_as_tuple( "pppoe_pool2" ),
        std::forward_as_tuple( "100.66.0.10", "100.66.0.255" ) );

    YAML::Node config;
    config[ "PPPOEPolicy" ] = pppoe_pol;
    config[ "AAAConf" ] = aaa_conf;

    std::ofstream fout("config.yaml");
    fout << config << std::endl;
}

int main( int argc, char *argv[] ) {
    conf_init();
    YAML::Node config = YAML::LoadFile( "config.yaml" );

    io_service io;
    runtime = std::make_shared<PPPOERuntime>( "pppoe-cp", io );

    // At this point all the config lies here
    runtime->pppoe_conf = std::make_shared<PPPOEPolicy>();
    runtime->pppoe_conf->ac_name = "vBNG AC PPPoE";
    runtime->pppoe_conf->insert_cookie = true;
    runtime->pppoe_conf->ignore_service_name = true;
    runtime->logger = std::make_unique<Logger>();
    runtime->logger->setLevel( LOGL::INFO );
    runtime->logger->logInfo() << LOGS::MAIN << "Starting PPP control plane daemon..." << std::endl;

    // LCP options
    runtime->lcp_conf = std::make_shared<LCPPolicy>();

    //runtime->aaa = std::make_shared<AAA>( 0x6440000A, 0x644000FE, 0x08080808, 0x01010101 );
    std::vector<std::string> files = {
        "/usr/share/freeradius/dictionary.rfc2865",
        "/usr/share/freeradius/dictionary.rfc2869",
        "/usr/share/freeradius/dictionary.ericsson.ab"
    };

    RadiusDict dict { files };
    runtime->aaa = std::make_shared<AAA>( config[ "AAAConf" ].as<AAAConf>() );
    runtime->vpp = std::make_shared<VPPAPI>();

    EVLoop loop( io );

    while( !interrupted ) {
        io.run();
    }

    return 0;
}
