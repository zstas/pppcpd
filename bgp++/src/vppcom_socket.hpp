using pkt_queue = std::deque<std::vector<uint8_t>>;

enum class op_type : uint8_t {
    READ,
    WRITE,
    ERROR
};

struct op {
    op_type type;
    uint32_t socket;
    bool is_listener;
    std::function<void()> func;

    op() = default;
    op( uint32_t s, op_type t):
        socket( s ),
        type( t ),
        is_listener( false )
    {}

    op( uint32_t s, op_type t, bool l ):
        socket( s ),
        type( t ),
        is_listener( l )
    {}
};

struct vppcom_service : public io_context::service {
    explicit vppcom_service( io_context &ctx );
    ~vppcom_service();
    static boost::asio::io_service::id id;
    void start();
    void run_epoll();

    void process_events( uint32_t fd, op_type op );
    void process_accept( op &operation );
    void schedule_event( op &&operation );

private:
    boost::scoped_ptr<boost::asio::io_service::work> work;
    boost::asio::io_service &async_io_service;
    std::thread thread;

    std::deque<op> scheduled_ops;
    std::deque<op> incoming_ops;

    // vppcom
    int epoll_fd;
};

struct vppcom_session {
    uint32_t sock;
    vppcom_endpt_t local;
    vppcom_endpt_t remote;
    vppcom_service &io;

    vppcom_session( vppcom_service &ctx ):
        io( ctx ) 
    {}

    vppcom_session( vppcom_service &ctx, uint32_t s ):
        io( ctx ),
        sock( s )
    {}
};

struct vppcom_listener {
    uint32_t sock;
    boost::asio::ip::basic_endpoint<boost::asio::ip::tcp> endpoint;
    vppcom_endpt_t local;
    vppcom_service &io;

    vppcom_listener( vppcom_service &ctx, boost::asio::ip::basic_endpoint<boost::asio::ip::tcp> e ):
        io( ctx ),
        endpoint( std::move( e ) )
    {
        if( !endpoint.address().is_v4() ) {
            throw "IPv6 is not supported";
        }
        uint32_t address = e.address().to_v4().to_uint();
        local.ip = reinterpret_cast<uint8_t*>( &address );
        local.port = bswap16( e.port() );
        local.is_ip4 = 1;
        local.parent_handle = 0; // ??
        local.is_cut_thru = 0; // ??
        sock = vppcom_session_create( 0, 1 );
        auto ret = vppcom_session_bind( sock, &local );
        ret = vppcom_session_listen( sock, 0 );
    }

    void async_accept( vppcom_session &s, std::function<void( boost::system::error_code &ec)> func );
    void on_accept( vppcom_session &s, std::function<void( boost::system::error_code &ec)> func );
};