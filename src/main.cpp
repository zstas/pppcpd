#include <memory>
#include <string>
#include <fstream>
#include <boost/program_options.hpp>

#include <yaml-cpp/yaml.h>
#include "yaml.hpp"

#include "main.hpp"
#include "runtime.hpp"
#include "evloop.hpp"
#include "cli.hpp"

// Some global vars
std::shared_ptr<PPPOERuntime> runtime;
std::atomic_bool interrupted { false };

static void conf_init() {
    PPPOEGlobalConf global_conf;

    global_conf.tap_name = "tap0";
    
    global_conf.default_pppoe_conf.ac_name = "vBNG AC PPPoE";
    global_conf.default_pppoe_conf.insert_cookie = true;
    global_conf.default_pppoe_conf.ignore_service_name = true;
    global_conf.default_pppoe_conf.service_name = { "inet", "pppoe" };

    PPPOELocalTemplate pppoe_template;
    pppoe_template.framed_pool = "pppoe_pool1";
    pppoe_template.dns1 = address_v4_t::from_string( "8.8.8.8" );
    pppoe_template.dns2 = address_v4_t::from_string( "1.1.1.1" );

    global_conf.aaa_conf.local_template.emplace( std::move( pppoe_template ) );
    global_conf.aaa_conf.method = { AAA_METHODS::RADIUS, AAA_METHODS::NONE };
    global_conf.aaa_conf.pools.emplace( std::piecewise_construct,
        std::forward_as_tuple( "pppoe_pool1" ),
        std::forward_as_tuple( "100.64.0.10", "100.64.255.255" ) );
    global_conf.aaa_conf.pools.emplace( std::piecewise_construct,
        std::forward_as_tuple( "pppoe_pool2" ),
        std::forward_as_tuple( "100.66.0.10", "100.66.0.255" ) );

    global_conf.aaa_conf.dictionaries = {
        "/usr/share/freeradius/dictionary.rfc2865",
        "/usr/share/freeradius/dictionary.rfc2866",
        "/usr/share/freeradius/dictionary.rfc2869",
        "/usr/share/freeradius/dictionary.ericsson.ab"
    };

    global_conf.aaa_conf.auth_servers.emplace( std::piecewise_construct,
        std::forward_as_tuple( "main_auth_1" ),
        std::forward_as_tuple( "127.0.0.1", 1812, "testing123" ) );
    
    global_conf.aaa_conf.acct_servers.emplace( std::piecewise_construct,
        std::forward_as_tuple( "main_acct_1" ),
        std::forward_as_tuple( "127.0.0.1", 1813, "testing123" ) );

    {
        InterfaceConf iconf;
        iconf.device = "GigabitEthernet0/8/0";
        iconf.mtu.emplace( 1500 );
        iconf.vlans.emplace_back( 200 );
        iconf.vlans.emplace_back( 201 );
        iconf.vlans.emplace_back( 202 );
        iconf.unnumbered_on_wan = true;
        global_conf.interfaces.push_back( std::move( iconf ) );
    }

    {
        InterfaceConf iconf;
        iconf.device = "GigabitEthernet0/9/0";
        iconf.mtu.emplace( 1500 );
        iconf.conf_as_subif.emplace( 150 );
        iconf.gateway.emplace( boost::asio::ip::make_address_v4( "10.0.0.1" ) );
        iconf.address.emplace( boost::asio::ip::make_network_v4( "10.0.0.2/24" ) );
        iconf.is_wan = true;
        global_conf.interfaces.push_back( std::move( iconf ) );
    }

    YAML::Node config;
    config = global_conf;

    std::ofstream fout("config.yaml");
    fout << config << std::endl;
}

int main( int argc, char *argv[] ) {
    std::string path_config { "config.yaml" };

    boost::program_options::options_description desc {
        "PPPoE control plane daemon.\n"
        "This daemon works with VPP PPPoE Plugin to process PPPoE connections. All configuration is available through config file. You can generate sample configuration to see all the parameters.\n"
        "\n"
        "Arguments"
    };
    desc.add_options()
    ( "path,p", boost::program_options::value( &path_config), "Path to config: default is \"config.yaml\"" )
    ( "genconf,g", "Generate a sample configuration" )
    ( "help,h", "Print this message" )
    ;

    boost::program_options::variables_map vm;
    boost::program_options::store( boost::program_options::parse_command_line( argc, argv, desc ), vm );

    if( vm.count( "help" ) ) {  
        std::cout << desc << "\n";
        return 0;
    }

    if( vm.count( "genconf" ) ) {
        conf_init();
        return 0;
    }

    YAML::Node config = YAML::LoadFile( path_config );

    io_service io;
    runtime = std::make_shared<PPPOERuntime>( config.as<PPPOEGlobalConf>(), io );

    // LCP options
    runtime->lcp_conf = std::make_shared<LCPPolicy>();
    runtime->lcp_conf->authCHAP = true;

    EVLoop loop( io );
    std::remove( "/var/run/pppcpd.sock" );
    CLIServer cli { io, "/var/run/pppcpd.sock" };

    while( !interrupted ) {
        io.run();
    }

    return 0;
}
