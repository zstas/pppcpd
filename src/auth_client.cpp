#include <set>
#include <iostream>

#include "auth_client.hpp"
#include "utils.hpp"
#include "net_integer.hpp"
#include "radius_dict.hpp"
#include "request_response.hpp"
#include "aaa.hpp"
#include "runtime.hpp"

extern std::shared_ptr<PPPOERuntime> runtime;

static std::string acct_auth_process( const std::vector<uint8_t> &pkt, const std::vector<uint8_t> req_attrs, const std::string &secret ) {
    std::string check { pkt.begin(), pkt.begin() + 4 };
    check.reserve( 128 );
    check.insert( check.end(), 16, 0 );
    check.insert( check.end(), req_attrs.begin(), req_attrs.end() );
    check.insert( check.end(), secret.begin(), secret.end() );
    return md5( check );
}

AuthClient::AuthClient( io_service& i, const address_v4_t& ip_address, uint16_t port, std::string s, RadiusDict d ): 
    io( i ), 
    socket( i, boost::asio::ip::udp::endpoint( boost::asio::ip::udp::v4(), 0 ) ),
    endpoint( ip_address, port ),
    secret( std::move( s )),
    dict( std::move( d ) ),
    last_id( 0 )
{}

AuthClient::~AuthClient()
{
	socket.close();
}

void AuthClient::send( const std::vector<uint8_t> &msg ) {
	socket.send_to( boost::asio::buffer( msg, msg.size() ), endpoint );
    receive();
}

void AuthClient::receive() {
    socket.async_receive_from( boost::asio::buffer( buf, buf.size() ), endpoint, std::bind( &AuthClient::on_rcv, this, std::placeholders::_1, std::placeholders::_2 ) );
}

// Incoming packet should be in buf
bool AuthClient::checkRadiusAnswer( const authenticator_t &req_auth, const authenticator_t &res_auth, const std::vector<uint8_t> &avp ) {
    std::string check { buf.begin(), buf.begin() + 4 };
    check.reserve( 128 );
    check.insert( check.end(), req_auth.begin(), req_auth.end() );
    check.insert( check.end(), avp.begin(), avp.end() );
    check.insert( check.end(), secret.begin(), secret.end() );
    auto hash_str = md5( check );
    std::vector<uint8_t> hash_to_check{ hash_str.begin(), hash_str.end() };

    if( std::equal( res_auth.begin(), res_auth.end(), hash_to_check.begin() ) ) {
        return true;
    } 
    return false;
}

void AuthClient::on_rcv( boost::system::error_code ec, size_t size ) {
    if( ec ) {
        runtime->logger->logError() << LOGS::RADIUS << "Socket error: " << ec.message() << std::endl;
        return;
    }

    auto pkt = reinterpret_cast<RadiusPacket*>( buf.data() );
    runtime->logger->logInfo() << LOGS::RADIUS << pkt << std::endl;

    auto const &it = callbacks.find( pkt->id );
    if( it == callbacks.end() ) {
        return;
    }
    auto &auth_authenticator = it->second.auth;

    std::vector<uint8_t> avp_buf { buf.begin() + sizeof( RadiusPacket ), buf.begin() + pkt->length.native() };

    if( !checkRadiusAnswer( it->second.auth, pkt->authenticator, avp_buf ) ) {
        runtime->logger->logError() << LOGS::RADIUS << "Answer is not correct, check the RADIUS secret" << std::endl;
        return;
    }

    it->second.response( pkt->code, std::move( avp_buf ) );
    it->second.timer.cancel();
}

void AuthClient::expire_check( boost::system::error_code ec, uint8_t id ) {
    auto const &it = callbacks.find( id );
    if( ec ) {
        if( ec != boost::system::errc::operation_canceled ) {
            runtime->logger->logError() << LOGS::RADIUS << "Error on expiring timer: " << ec.message() << std::endl;
        }
    } else {
        if( it != callbacks.end() ) {
            it->second.error( "Timeout for this radius request" );
        }
    }
    if( it != callbacks.end() ) {
        callbacks.erase( it );
    }
    if( callbacks.empty() ) {
        socket.cancel();
    }
}