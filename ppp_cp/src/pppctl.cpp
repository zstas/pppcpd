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
        boost::asio::io_context io;

        stream_protocol::endpoint endpoint( unix_socket_path );
        stream_protocol::socket socket( io );
        socket.connect( endpoint );
        if( !socket.is_open() ) {
            std::cerr << "Cannot connect to unix socket: " << unix_socket_path << std::endl;
            return 1;
        }

        while( cmd != "exit" ) {
            std::cout << greeting;
            std::getline( std::cin, cmd );
            boost::asio::write( socket, boost::asio::buffer( cmd ) );
            std::string buf;
            auto n = boost::asio::read_until( socket, boost::asio::dynamic_buffer( buf ), "\r\n\r\n" );
            std::cout << buf;
        }

    } catch( std::exception &e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}