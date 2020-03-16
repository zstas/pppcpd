#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <list>
#include <memory>

using io_context = boost::asio::io_context;
using acceptor = boost::asio::ip::tcp::acceptor;
using endpoint = boost::asio::ip::tcp::endpoint;
using socket_tcp = boost::asio::ip::tcp::socket;
using error_code = boost::system::error_code;

using namespace std::string_literals;

#include "connection.hpp"
#include "packet.hpp"
#include "utils.hpp"

struct main_loop {
    io_context io;
    acceptor accpt;
    socket_tcp sock;
    std::list<std::weak_ptr<bgp_connection>> conns;

    main_loop( int port );

    void run(); 
    void on_accept( error_code ec );
};