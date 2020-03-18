enum class FSM_STATE {
    IDLE,
    CONNECT,
    ACTIVE,
    OPENSENT,
    OPENCONFIRM,
    ESTABLISHED,
};

struct fsm {
    FSM_STATE state;
    bool admin_disabled;

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

    fsm( io_context &io, bool status = false );
};