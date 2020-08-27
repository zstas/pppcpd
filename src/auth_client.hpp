#ifndef AUTH_CLIENT_HPP
#define AUTH_CLIENT_HPP

#include <map>
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/udp.hpp>

using io_service = boost::asio::io_service;
using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

#include "log.hpp"
#include "radius_packet.hpp"
#include "radius_dict.hpp"

class RadiusDict;

using ResponseHandler = std::function<void( RADIUS_CODE, std::vector<uint8_t> )>;
using ErrorHandler = std::function<void( std::string )>;

template<typename T>
std::vector<uint8_t> serialize( const RadiusDict &dict, const T &v, const authenticator_t &a, const std::string &secret );

template<typename T>
T deserialize( const RadiusDict &dict, std::vector<uint8_t> &v );

struct response_t {
    ResponseHandler response;
    ErrorHandler error;
    boost::asio::steady_timer timer;
    authenticator_t auth;

    response_t( io_service &io, ResponseHandler r, ErrorHandler t, authenticator_t a ):
        response( std::move( r ) ),
        error( std::move( t ) ),
        timer( io ),
        auth( std::move( a ) )
    {}
};

class AuthClient
{
public:
	AuthClient( io_service &i, const address_v4_t &ip_address, uint16_t port, std::string s, RadiusDict d );
	~AuthClient();

    template<typename T>
    void request( const T &req, ResponseHandler handler, ErrorHandler error ) {
        last_id++;
        std::vector<uint8_t> pkt;
        pkt.resize( sizeof( RadiusPacket ) );
        auto pkt_hdr = reinterpret_cast<RadiusPacket*>( pkt.data() );
        pkt_hdr->code = RADIUS_CODE::ACCESS_REQUEST;
        pkt_hdr->id = last_id;
        pkt_hdr->authenticator = generateAuthenticator();

        auto seravp = serialize( dict, req, pkt_hdr->authenticator, secret );
        pkt.insert( pkt.end(), seravp.begin(), seravp.end() );

        pkt_hdr = reinterpret_cast<RadiusPacket*>( pkt.data() );
        pkt_hdr->length = pkt.size();

        if( auto const &[ it, success ] = callbacks.emplace( 
            std::piecewise_construct, 
            std::forward_as_tuple( last_id ), 
            std::forward_as_tuple( io, std::move( handler ), std::move( error ), pkt_hdr->authenticator ) 
        ); success ) {
            it->second.timer.expires_from_now( std::chrono::seconds( 5 ) );
            it->second.timer.async_wait( std::bind( &AuthClient::expire_check, this, std::placeholders::_1, last_id ) );
        } else {
            // todo: err handling
            return;
        }
        send( pkt );
    }

    template<typename T>
    void acct_request( const T &req, ResponseHandler handler, ErrorHandler error ) {
        last_id++;
        std::vector<uint8_t> pkt;
        pkt.resize( sizeof( RadiusPacket ) );
        auto pkt_hdr = reinterpret_cast<RadiusPacket*>( pkt.data() );
        pkt_hdr->code = RADIUS_CODE::ACCOUNTING_REQUEST;
        pkt_hdr->id = last_id;

        auto seravp = serialize( dict, req, pkt_hdr->authenticator, secret );
        pkt.insert( pkt.end(), seravp.begin(), seravp.end() );

        pkt_hdr = reinterpret_cast<RadiusPacket*>( pkt.data() );
        pkt_hdr->length = pkt.size();

        auto temp = acct_auth_process( pkt, seravp, secret );
        std::copy( temp.begin(), temp.end(), pkt_hdr->authenticator.begin() );

        if( auto const &[ it, success ] = callbacks.emplace( 
            std::piecewise_construct, 
            std::forward_as_tuple( last_id ), 
            std::forward_as_tuple( io, std::move( handler ), std::move( error ), pkt_hdr->authenticator ) 
        ); success ) {
            it->second.timer.expires_from_now( std::chrono::seconds( 5 ) );
            it->second.timer.async_wait( std::bind( &AuthClient::expire_check, this, std::placeholders::_1, last_id ) );
        } else {
            // todo: err handling
            return;
        }
        send( pkt );
    }

private:
    void expire_check( boost::system::error_code ec, uint8_t id );
    void on_rcv( boost::system::error_code ec, size_t size );
    bool checkRadiusAnswer( const authenticator_t &req_auth, const authenticator_t &res_auth, const std::vector<uint8_t> &avp );
	void send( const std::vector<uint8_t> &msg );
    void receive();

    uint8_t last_id;
    RadiusDict dict;
    std::string secret;
    std::map<uint8_t,response_t> callbacks;
    std::array<uint8_t,1500> buf;
	io_service &io;
	boost::asio::ip::udp::socket socket;
	boost::asio::ip::udp::endpoint endpoint;
};

#endif