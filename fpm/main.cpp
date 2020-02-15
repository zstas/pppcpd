#include "main.hpp"

struct Netlink {

    static int data_cb_route( const struct nlmsghdr *nlh, void *data ) {
        struct rtmsg *rm = reinterpret_cast<struct rtmsg *>( mnl_nlmsg_get_payload( nlh ) );
        struct nlattr *attr = reinterpret_cast<struct nlattr *>( mnl_nlmsg_get_payload_offset( nlh, sizeof( struct rtmsg ) ) );
        while( mnl_attr_ok( attr, reinterpret_cast<char*>( mnl_nlmsg_get_payload_tail( nlh ) ) - reinterpret_cast<char*>( attr ) ) ) {
            int type = mnl_attr_get_type( attr );
            switch( type ) {
            case RTA_DST:
                printf( "%02x\n", mnl_attr_get_u32( attr ) );
                break;
            case RTA_GATEWAY:
                printf( "%02x\n", mnl_attr_get_u32( attr ) );
                break;
            }
            attr = mnl_attr_next( attr );
        }
        return MNL_CB_OK;
    }

    static int data_cb( const struct nlmsghdr *nlh, void *data )
    {
        
    	switch( nlh->nlmsg_type ) {
    	case RTM_NEWROUTE:
    	case RTM_DELROUTE:
            return data_cb_route( nlh, data );
    	case RTM_NEWNEIGH:
    	case RTM_DELNEIGH:
            std::cout << "NEIGH" << std::endl;
            break;
    		//return data_cb_neighbor(nlh, data);
    	case RTM_NEWADDR:
    	case RTM_DELADDR:
            std::cout << "ADDR" << std::endl;
            break;
    		//return data_cb_address(nlh, data);
    	default:
            break;
    	}
        return MNL_CB_OK;
    }


    void process( std::vector<uint8_t> &v) {
        int ret;
        fpm_msg_hdr_t *hdr;
        hdr = reinterpret_cast<fpm_msg_hdr_t *>( v.data() );
        if( hdr->msg_type == FPM_MSG_TYPE_NETLINK ) {
            do {
                ret = mnl_cb_run( fpm_msg_data( hdr ), fpm_msg_len( hdr ), 0, 0, data_cb, nullptr );
            } while( ret <= MNL_CB_STOP );
            std::cout << "mnl_cb_run: " << ret << std::endl;
        } else if( hdr->msg_type == FPM_MSG_TYPE_PROTOBUF ) {
            fpm::Message m;
            m.ParseFromArray( fpm_msg_data( hdr ), fpm_msg_len( hdr ) );
            m.PrintDebugString();
        }
    }
};

class FPM_conn {
private:
    boost::asio::ip::tcp::socket socket;
    std::array<uint8_t,1500> buf;
public:
    FPM_conn( boost::asio::ip::tcp::socket s ):
        socket( std::move( s ) )
    {

    }

    void start() {
        socket.async_receive( boost::asio::buffer( buf ), std::bind( &FPM_conn::on_read, this, std::placeholders::_1, std::placeholders::_2 ) );
    }

    void on_read( boost::system::error_code ec, std::size_t length ) {
        std::cout << "rcd bytes: " << length << std::endl;
        std::vector<uint8_t> v { buf.data(), buf.data() + length };
        Netlink nl;
        nl.process( v );
        start();
    }
};

class FPM_mgr {
private:
    boost::asio::io_context io;
    boost::asio::ip::address addr;
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;

    std::queue<FPM_conn> connections;
public:
    FPM_mgr():
        addr( boost::asio::ip::address_v4::any() ),
        acceptor( io, boost::asio::ip::tcp::endpoint( boost::asio::ip::tcp::v4(), 31337 ) ),
        socket( io )
    {
        acceptor.async_accept( socket, std::bind( &FPM_mgr::on_accept, this, std::placeholders::_1 ) );
        io.run();
    }

    void on_accept( boost::system::error_code ec ) {
        auto &it = connections.emplace( std::move( socket ) );
        it.start();
        acceptor.async_accept( socket, std::bind( &FPM_mgr::on_accept, this, std::placeholders::_1 ) );
    }
};

int main( int argc, char *argv[] ) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    FPM_mgr fpm;
    return 0;
}