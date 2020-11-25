#ifndef EVLOOP_HPP
#define EVLOOP_HPP

#include <queue>
#include <atomic>

#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/basic_raw_socket.hpp>

using io_service = boost::asio::io_service;

extern std::atomic_bool interrupted;

struct PPPOEQ {
    std::queue<std::vector<uint8_t>> queue;

    void push( std::vector<uint8_t> pkt ) {
        queue.push( std::move( pkt ) );
    }

    std::vector<uint8_t> pop() {
        auto ret = queue.front();
        queue.pop();
        return ret;
    }

    bool empty() {
        return queue.empty();
    }
};

class EVLoop {
public:
    EVLoop( io_service &i );
    void generic_receive( boost::system::error_code ec, std::size_t len, uint16_t outer_vlan, uint16_t inner_vlan );
    void receive_pppoe( boost::system::error_code ec );
    void receive_ppp( boost::system::error_code ec );
    void periodic( boost::system::error_code ec );
    void on_signal( const boost::system::error_code &ec, int signal );

private:
    io_service &io;
    boost::asio::signal_set signals;
    std::array<uint8_t,1500> pktbuf;
    boost::asio::generic::raw_protocol pppoed;
    boost::asio::generic::raw_protocol pppoes;
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_pppoe;
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_ppp;
    boost::asio::steady_timer periodic_callback;
};

#endif