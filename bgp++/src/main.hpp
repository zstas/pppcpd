#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/bind.hpp>
#include <list>
#include <memory>
#include <optional>
#include <yaml-cpp/yaml.h>

#include <vcl/vppcom.h>

using io_context = boost::asio::io_context;
using acceptor = boost::asio::ip::tcp::acceptor;
using endpoint = boost::asio::ip::tcp::endpoint;
using socket_tcp = boost::asio::ip::tcp::socket;
using error_code = boost::system::error_code;
using address_v4 = boost::asio::ip::address_v4;
using prefix_v4 = boost::asio::ip::network_v4;
using timer = boost::asio::steady_timer;
using stream_descriptor = boost::asio::posix::stream_descriptor;

using namespace std::string_literals;

#include "packet.hpp"
#include "utils.hpp"
#include "config.hpp"
#include "fsm.hpp"
#include "table.hpp"
#include "vpp.hpp"
#include "vppcom_socket.hpp"

struct main_loop {
    // asio
    io_context io;
    acceptor accpt;
    socket_tcp sock;

    // vpp
    vppcom_service vpp_io;
    vppcom_listener vpp_accpt;
    vppcom_session vpp_sock;

    global_conf &conf;
    bgp_table_v4 table;
    std::map<address_v4,std::shared_ptr<bgp_fsm>> neighbours;

    main_loop( global_conf &c );

    void run(); 
    void on_accept( error_code ec );
    void on_vpp_accept( error_code ec );
};