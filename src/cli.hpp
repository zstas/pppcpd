#ifndef CLI_HPP
#define CLI_HPP

#include <iostream>
#include <iomanip>
#include <memory>
#include <boost/asio.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include "vpp_types.hpp"

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
    std::string data;
    std::string error;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & type;
        archive & cmd;
        archive & data;
        archive & error;
    }
};

struct PPPOE_SESSION_DUMP {
    uint32_t aaa_session_id;
    uint16_t session_id;
    std::string cookie;
    std::string username;
    uint32_t address;
    uint32_t ifindex;
    std::string vrf;
    std::string unnumbered;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & aaa_session_id;
        archive & session_id;
        archive & cookie;
        archive & username;
        archive & address;
        archive & ifindex;
        archive & vrf;
        archive & unnumbered;
    }
};

struct AAA_SESSION_DUMP {
    uint32_t session_id;
    std::string username;
    std::string address;
    std::string dns1;
    std::string dns2;
    std::string framed_pool;
    std::string vrf;
    std::string unnumbered;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & session_id;
        archive & username;
        archive & address;
        archive & dns1;
        archive & dns2;
        archive & framed_pool;
        archive & vrf;
        archive & unnumbered;
    }
};

struct GET_PPPOE_SESSION_RESP {
    std::vector<PPPOE_SESSION_DUMP> sessions;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & sessions;
    }
};

struct GET_VERSION_RESP {
    std::string version_string;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & version_string;
    }
};

struct GET_AAA_SESSIONS_RESP {
    std::vector<AAA_SESSION_DUMP> sessions;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & sessions;
    }
};

struct GET_VPP_IFACES_RESP {
    std::vector<VPPInterface> ifaces;

    template<class Archive>
    void serialize( Archive &archive, const unsigned int version ) {
        archive & ifaces;
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
    boost::asio::streambuf request;
};


#endif