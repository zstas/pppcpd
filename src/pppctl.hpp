#ifndef PPPCTL_HPP
#define PPPCTL_HPP

class CLIClient {
public:
    CLIClient( boost::asio::io_context &i, const std::string &path );
    std::string process_input( const std::string &input );
private:
    boost::asio::io_context &io;
    boost::asio::local::stream_protocol::endpoint endpoint;
    boost::asio::local::stream_protocol::socket socket;
};

#endif