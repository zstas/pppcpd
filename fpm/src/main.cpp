#include "main.hpp"



class FPM_conn {
private:
    boost::asio::ip::tcp::socket socket;
    std::array<uint8_t,1500> buf;
    Netlink nl;
public:
    FPM_conn( boost::asio::ip::tcp::socket s ):
        socket( std::move( s ) )
    {

    }

    void start() {
        socket.async_receive( boost::asio::buffer( buf ), std::bind( &FPM_conn::on_read, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void on_read( boost::system::error_code ec, std::size_t length ) {
        std::cout << "rcd bytes: " << length << std::endl;
        std::vector<uint8_t> v { buf.data(), buf.data() + length };
        nl.process( v );
        start();
    }
};

class FPM_mgr {
private:
    boost::asio::io_context io;
    boost::asio::ip::address addr;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;

    std::queue<FPM_conn> connections;
public:
    FPM_mgr():
        addr( boost::asio::ip::address_v4::any() ),
        acceptor( io, boost::asio::ip::tcp::endpoint( boost::asio::ip::tcp::v4(), 31337 ) ),
        socket( io )
    {
        acceptor.async_accept( socket, std::bind( &FPM_mgr::on_accept, this, std::placeholders::_1 ) );
        io.run();
    }

    void on_accept( boost::system::error_code ec ) {
        auto &it = connections.emplace( std::move( socket ) );
        it.start();
        acceptor.async_accept( socket, std::bind( &FPM_mgr::on_accept, this, std::placeholders::_1 ) );
    }
};

void log( const std::string &m ) {
    std::cout << m << std::endl;
}

int main( int argc, char *argv[] ) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    FPM_mgr fpm;
    return 0;
}