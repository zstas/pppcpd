#ifndef CLI_HPP
#define CLI_HPP

#include <iostream>
#include <iomanip>
#include <memory>
#include <boost/asio.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

using stream_protocol = boost::asio::local::stream_protocol;

enum class CLI_CMD_TYPE: uint8_t {
    REQUEST = 0,
    RESPONSE = 1,
};

enum class CLI_CMD: uint8_t {
    GET_VERSION,
    GET_PPPOE_SESSIONS,
    GET_AAA_SESSIONS,
    GET_VPP_IFACES,
};

struct CLI_MSG {
    CLI_CMD_TYPE type;
    CLI_CMD cmd;
    std::string response;
    std::string error;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & type;
        archive & cmd;
        archive & response;
        archive & error;
    }
};

template<typename T>
std::string serialize( const T &val ) {
    static auto const ser_flags = boost::archive::no_header | boost::archive::no_tracking;
    std::stringstream ss;
    boost::archive::binary_oarchive ser( ss, ser_flags );
    ser << val;
    return ss.str();
}

template<typename T>
T deserialize( const std::string &val ) {
    static auto const ser_flags = boost::archive::no_header | boost::archive::no_tracking;
    T out;
    std::istringstream ss( val );
    boost::archive::binary_iarchive deser{ ss, ser_flags };
    deser >> out;
    return out;
}

class CLIServer {
public:
    CLIServer( boost::asio::io_context &io_context, const std::string &path );

private:
    void do_accept();
    stream_protocol::acceptor acceptor_;
};

class CLISession: public std::enable_shared_from_this<CLISession> {
public:
    CLISession(stream_protocol::socket sock): 
        socket_(std::move(sock))
    {}

    void start();

private:
    void do_read();
    void do_write( std::shared_ptr<std::string> &out );
    void run_cmd( const std::string &cmd );

    stream_protocol::socket socket_;
    std::array<char, 1024> data_;
};


#endif