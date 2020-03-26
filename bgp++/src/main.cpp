#include "main.hpp"

main_loop::main_loop( global_conf &c ):
    conf( c ),
    accpt( io, endpoint( boost::asio::ip::tcp::v4(), c.listen_on_port ) ),
    sock( io )
{
    for( auto &nei: c.neighbours ) {
        neighbours.emplace( std::piecewise_construct, std::forward_as_tuple( nei.address ), std::forward_as_tuple( io, c, nei ) );
    }
}

void main_loop::run() {
    log( "Starting event loop" );
    accpt.async_accept( sock, std::bind( &main_loop::on_accept, this, std::placeholders::_1 ) );
    io.run();
}

void main_loop::on_accept( error_code ec ) {
    if( ec ) {
        std::cerr << "Error on accepting new connection: "s + ec.message() << std::endl;
    }
    auto const &remote_addr = sock.remote_endpoint().address().to_v4();
    auto const &nei_it = neighbours.find( remote_addr );
    if( nei_it == neighbours.end() ) {
        log( "Connection not from our peers, so dropping it." );
        sock.close();
    } else {
        auto new_conn = std::make_shared<bgp_connection>( std::move( sock ) );
        conns.emplace_back( new_conn );
        nei_it->second.place_connection( new_conn );
    }
    accpt.async_accept( sock, std::bind( &main_loop::on_accept, this, std::placeholders::_1 ) );
}

static void config_init() {
    global_conf new_conf;
    new_conf.listen_on_port = 179;
    new_conf.my_as = 31337;
    new_conf.hold_time = 60;
    new_conf.bgp_router_id = address_v4::from_string( "1.2.3.4" );

    bgp_neighbour_v4 bgp1;
    bgp1.remote_as = 31337;
    bgp1.address = address_v4::from_string( "127.0.0.1" );
    new_conf.neighbours.emplace_back( bgp1 );

    bgp1.address = address_v4::from_string( "8.8.8.8" );
    new_conf.neighbours.emplace_back( bgp1 );

    YAML::Node node;
    node = new_conf;
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
    for( auto const &n: conf.neighbours ) {
        log( "\tNeighbour: "s + n.address.to_string() + "\tAS: "s + std::to_string( n.remote_as ) );
    }
    try { 
        main_loop loop { conf };
        loop.run();
    } catch( std::exception &e ) {
        std::cerr << "Error on run event loop: "s + e.what() << std::endl;
    }
    return 0;
}