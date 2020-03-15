struct bgp_connection {
    socket_tcp sock;

    bgp_connection( socket_tcp s ):
        sock( std::move( s ) ) 
    {}
};