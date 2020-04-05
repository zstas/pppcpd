using pkt_queue = std::deque<std::vector<uint8_t>>;

typedef void *accept_handler(boost::system::error_code);

enum class op_type : uint8_t {
    READ,
    WRITE,
    ERROR
};

struct op {
    op_type type;
    uint32_t socket;
    std::function<void( boost::system::error_code &ec, ssize_t len )> func;

    op() = default;
    op( uint32_t s, op_type t):
        socket( s ),
        type( t )
    {}
};

struct vppcom_service : public io_context::service {
    explicit vppcom_service( io_context &ctx );
    ~vppcom_service();
    static boost::asio::io_service::id id;
    void start();
    void run_epoll();

    void process_events( uint32_t fd, op_type op );

private:
    boost::scoped_ptr<boost::asio::io_service::work> work;
    boost::asio::io_service async_io_service;
    std::thread thread;

    std::deque<op> scheduled_ops;
    std::deque<op> incoming_ops;

    std::map<uint32_t,vppcom_listener> listeners;
    std::map<uint32_t,vppcom_session> sessions;
    std::map<uint32_t,pkt_queue> ingress_queue;
    std::map<uint32_t,pkt_queue> egress_queue;

    // vppcom
    int epoll_fd;
};

struct vppcom_worker {
    io_context &io;
    stream_descriptor stream;
    int fd;

    vppcom_worker( io_context &i ):
        io( i ),
        stream( io, vppcom_worker_mqs_epfd() )
    {
        auto ret = vppcom_app_create( "bgp++ vppcom" );
        log( "app_create: "s + std::to_string( ret ) );
        fd = vppcom_epoll_create();
        stream.async_wait( boost::asio::posix::stream_descriptor::wait_read, std::bind( &vppcom_worker::callback, this, std::placeholders::_1 ) );
    }

    void callback( boost::system::error_code &ec );
};

struct vppcom_listener {
    uint32_t sock;
    vppcom_endpt_t local;
    io_context &io;

    vppcom_listener( io_context &ctx ):
        io( ctx ) 
    {}

    void async_accept( accept_handler func );
};

struct vppcom_session {
    uint32_t sock;
    vppcom_endpt_t local;
    vppcom_endpt_t remote;

    vppcom_session( uint32_t s, vppcom_endpt_t l, vppcom_endpt_t r  ):
        sock( s ),
        local( l ),
        remote( r )
    {}

    
};