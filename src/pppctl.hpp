#ifndef PPPCTL_HPP
#define PPPCTL_HPP

using cmd_callback = std::function<std::string(const std::map<std::string,std::string> &)>;

enum class CLINodeType {
    BEGIN,
    STATIC,
    ARGUMENT,
    END
};

struct CLINode : public std::enable_shared_from_this<CLINode> {
    explicit CLINode( CLINodeType t ):
        type( t )
    {}

    explicit CLINode( CLINodeType t, std::string tok ):
        type( t ),
        token( std::move( tok ) )
    {}

    explicit CLINode( CLINodeType t, cmd_callback cb ):
        type( t ),
        callback( cb )
    {}

    CLINode() = delete;

    CLINodeType type;
    std::string token;
    cmd_callback callback;

    std::vector<std::shared_ptr<CLINode>> next_nodes;
};

class CLICMD {
public:
    CLICMD();
    void add_cmd( const std::string &full_command, cmd_callback callback );
    std::string call_cmd( const std::string &cmd );
    std::vector<std::string> append_cmd( const std::string &cmd );
private:
    std::shared_ptr<CLINode> start_node;
};

class CLIClient {
public:
    CLIClient( boost::asio::io_context &i, const std::string &path );
    void process_input( const std::string &input );
private:
    void read_input();
    void on_read( const boost::system::error_code &ec, size_t len );
    void print_resp( const std::string &msg );
    void process_char( const char &ch );

    boost::asio::io_context &io;
    boost::asio::local::stream_protocol::endpoint endpoint;
    boost::asio::local::stream_protocol::socket socket;
    boost::asio::posix::stream_descriptor stdio;
    CLICMD cmd;
    boost::asio::streambuf input;
    std::string current_cmd;
};

#endif