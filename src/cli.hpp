#ifndef CLI_HPP
#define CLI_HPP

#include <iostream>
#include <iomanip>
#include <boost/asio.hpp>

#include "runtime.hpp"

using stream_protocol = boost::asio::local::stream_protocol;

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
    void do_write( std::string &out );
    void run_cmd( const std::string &cmd );

    stream_protocol::socket socket_;
    std::array<char, 1024> data_;
};


#endif