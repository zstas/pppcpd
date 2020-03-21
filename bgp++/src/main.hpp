#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include <list>
#include <memory>
#include <optional>
#include <yaml-cpp/yaml.h>

using io_context = boost::asio::io_context;
using acceptor = boost::asio::ip::tcp::acceptor;
using endpoint = boost::asio::ip::tcp::endpoint;
using socket_tcp = boost::asio::ip::tcp::socket;
using error_code = boost::system::error_code;
using address_v4 = boost::asio::ip::address_v4;
using timer = boost::asio::steady_timer;

using namespace std::string_literals;

#include "connection.hpp"
#include "packet.hpp"
#include "utils.hpp"
#include "config.hpp"
#include "fsm.hpp"

struct main_loop {
    io_context io;
    acceptor accpt;
    socket_tcp sock;
    global_conf &conf;
    std::list<std::weak_ptr<bgp_connection>> conns;

    main_loop( global_conf &c );

    void run(); 
    void on_accept( error_code ec );
};