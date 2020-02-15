#include "main.hpp"

int Netlink::data_cb_route( const struct nlmsghdr *nlh, void *data ) {
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

int Netlink::data_cb( const struct nlmsghdr *nlh, void *data )
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


void Netlink::process( std::vector<uint8_t> &v) {
    int ret;
    fpm_msg_hdr_t *hdr;
    hdr = reinterpret_cast<fpm_msg_hdr_t *>( v.data() );
    if( hdr->msg_type == FPM_MSG_TYPE_NETLINK ) {
        log( "we don't support netlink yet" );
    } else if( hdr->msg_type == FPM_MSG_TYPE_PROTOBUF ) {
        fpm::Message m;
        m.ParseFromArray( fpm_msg_data( hdr ), fpm_msg_len( hdr ) );
        m.PrintDebugString();
        if( m.type() == fpm::Message_Type::Message_Type_ADD_ROUTE ) {
            log( "adding route" );
            vpp.add_route( m );
        } else if( m.type() == fpm::Message_Type::Message_Type_DELETE_ROUTE ) {
            log( "deleting route" );
            vpp.del_route( m );
        }
    }
}
