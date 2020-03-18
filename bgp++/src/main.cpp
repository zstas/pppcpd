#include "main.hpp"

main_loop::main_loop( int port ):
    accpt( io, endpoint( boost::asio::ip::tcp::v4(), port ) ),
    sock( io )
{}

void main_loop::run() {
    log( "Starting event loop" );
    accpt.async_accept( sock, std::bind( &main_loop::on_accept, this, std::placeholders::_1 ) );
    io.run();
}

void main_loop::on_accept( error_code ec ) {
    if( ec ) {
        std::cerr << "Error on accepting new connection: "s + ec.message() << std::endl;
    }
    auto new_conn = std::make_shared<bgp_connection>( std::move( sock ) );
    conns.emplace_back( new_conn );
    new_conn->start();
    accpt.async_accept( sock, std::bind( &main_loop::on_accept, this, std::placeholders::_1 ) );
}

static void config_init() {
    global_conf conf;
    conf.listen_on_port = 179;
    conf.my_as = 31337;
    conf.bgp_router_id = address_v4::from_string( "1.2.3.4" );

    bgp_neighbour_v4 bgp1;
    bgp1.remote_as = 31337;
    bgp1.address = address_v4::from_string( "8.8.4.4" );
    conf.neighbours.emplace_back( bgp1 );

    bgp1.address = address_v4::from_string( "8.8.8.8" );
    conf.neighbours.emplace_back( bgp1 );

    YAML::Node node;
    node = conf;
    std::ofstream fout("config.yaml");
    fout << node << std::endl;
}

int main( int argc, char *argv[] ) {
    config_init();    
    global_conf conf;
    try {
        YAML::Node config = YAML::LoadFile("config.yaml");
        conf = config.as<global_conf>();
    } catch( std::exception &e ) {
        log( "Cannot load config: "s + e.what() );
        return 1;
    }

    log( "Loaded conf: " );
    log( "\tMy AS: "s + std::to_string( conf.my_as ) );
    log( "\tListen on port: "s + std::to_string( conf.listen_on_port ) );
    log( "\tBGP Router ID: "s + conf.bgp_router_id.to_string() );
    try { 
        main_loop loop { conf.listen_on_port };
        loop.run();
    } catch( std::exception &e ) {
        std::cerr << "Error on run event loop: "s + e.what() << std::endl;
    }
    return 0;
}