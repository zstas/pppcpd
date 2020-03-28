#ifndef FSM_HPP_
#define FSM_HPP_

#include "table.hpp"

enum class FSM_STATE {
    IDLE,
    CONNECT,
    ACTIVE,
    OPENSENT,
    OPENCONFIRM,
    ESTABLISHED,
};

struct bgp_fsm : public std::enable_shared_from_this<bgp_fsm> {
    FSM_STATE state;
    global_conf &gconf;
    bgp_neighbour_v4 &conf;
    bgp_table_v4 table;

    std::array<uint8_t,65535> buffer;
    std::optional<socket_tcp> sock;

    // counters
    uint64_t ConnectRetryCounter;

    // timers
    timer ConnectRetryTimer;
    timer HoldTimer;
    timer KeepaliveTimer;

    // config
    uint16_t ConnectRetryTime;
    uint16_t HoldTime;
    uint16_t KeepaliveTime;

    bgp_fsm( io_context &io, global_conf &g, bgp_neighbour_v4 &c );
    void place_connection( socket_tcp s );

    void start_keepalive_timer();
    void on_keepalive_timer( error_code ec );

    void on_receive( error_code ec, std::size_t length );
    void on_send( std::shared_ptr<std::vector<uint8_t>> pkt, error_code ec, std::size_t length );
    void do_read();

    void rx_open( bgp_packet &pkt );
    void tx_open();

    void rx_keepalive( bgp_packet &pkt );
    void tx_keepalive();

    void rx_update( bgp_packet &pkt );
};

#endif