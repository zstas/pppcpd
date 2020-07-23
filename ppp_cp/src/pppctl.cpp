#include <iostream>
#include <string>
#include <boost/asio.hpp>

using stream_protocol = boost::asio::local::stream_protocol;

inline constexpr char greeting[] { "pppctl# " };
inline constexpr char unix_socket_path[] { "/var/run/pppcpd.sock" };

int main( int argc, char *argv[] ) {
    std::cout << "Control utility of ppp control daemon" << std::endl;
    std::string cmd;

    try {
        stream_protocol::endpoint endpoint( unix_socket_path );
        stream_protocol::iostream socket( endpoint );
        if( !socket ) {
            std::cerr << "Cannot connect to unix socket: " << unix_socket_path << std::endl;
            return 1;
        }

        while( cmd != "exit" ) {
            std::cout << greeting;
            std::cin >> cmd;
        }

    } catch( std::exception &e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}