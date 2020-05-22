#ifndef EVLOOP_HPP
#define EVLOOP_HPP

extern std::atomic_bool interrupted;

struct PPPOEQ {
    std::mutex mutex;
    std::condition_variable cond;
    std::queue<std::vector<uint8_t>> queue;

    void push( std::vector<uint8_t> pkt ) {
        std::lock_guard lg( mutex );
        queue.push( std::move( pkt ) );
        // cond.notify_one();
    }

    std::vector<uint8_t> pop() {
        std::lock_guard lg( mutex );
        // while( queue.empty() ) {
        //     cond.wait_for( lg, std::chrono::seconds( 1 ) );
        //     if( interrupted ) {
        //         exit( 0 );
        //     }
        // }
        auto ret = queue.front();
        queue.pop();
        return ret;
    }

    bool empty() {
        std::lock_guard lg( mutex );
        return queue.empty();
    }
};

class EVLoop {
private:
    io_service &io;
    boost::asio::signal_set signals{ io, SIGTERM, SIGINT };
    std::array<uint8_t,1500> pktbuf;

    boost::asio::generic::raw_protocol pppoed { PF_PACKET, SOCK_RAW };
    boost::asio::generic::raw_protocol pppoes { PF_PACKET, SOCK_RAW };
    // boost::asio::generic::raw_protocol vlan { PF_PACKET, SOCK_RAW };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_pppoe { io, pppoed };
    boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_ppp { io, pppoes };
    // boost::asio::basic_raw_socket<boost::asio::generic::raw_protocol> raw_sock_vlan { io, vlan };
    boost::asio::steady_timer periodic_callback{ io, boost::asio::chrono::seconds( 1 ) };
public:
    EVLoop( io_service &i );
    void generic_receive( boost::system::error_code ec, std::size_t len, uint16_t outer_vlan, uint16_t inner_vlan );
    void receive_pppoe( boost::system::error_code ec );
    void receive_ppp( boost::system::error_code ec );
    void periodic( boost::system::error_code ec );
};

#endif