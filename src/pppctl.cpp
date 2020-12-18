#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>

using address_v4_t = boost::asio::ip::address_v4;
using network_v4_t = boost::asio::ip::network_v4;

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/array.hpp>

#include <boost/algorithm/string.hpp>

#include "pppctl.hpp"
#include "cli.hpp"
#include "string_helpers.hpp"

inline constexpr char greeting[] { "pppctl# " };
inline constexpr char unix_socket_path[] { "/var/run/pppcpd.sock" };

static std::vector<std::string> split( const std::string &input ) {
    std::vector<std::string> tokens;
    boost::split( tokens, input, boost::is_any_of( " " ) );

    tokens.erase(
        std::remove_if(
            tokens.begin(),
            tokens.end(),
            []( const std::string &i ) {
                return i.empty();
            }
        ),
        tokens.end()
    );

    return tokens;
}

std::string get_version( const std::map<std::string,std::string> &args ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_VERSION;
    return serialize( out_msg );
}

std::string get_interfaces( const std::map<std::string,std::string> &args ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_VPP_IFACES;
    return serialize( out_msg );
}

std::string get_pppoe_sessions( const std::map<std::string,std::string> &args ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_PPPOE_SESSIONS;
    return serialize( out_msg );
}

std::string get_aaa_sessions( const std::map<std::string,std::string> &args ) {
    CLI_MSG out_msg;
    out_msg.type = CLI_CMD_TYPE::REQUEST;
    out_msg.cmd = CLI_CMD::GET_AAA_SESSIONS;
    return serialize( out_msg );
}

CLICMD::CLICMD():
    start_node( std::make_shared<CLINode>( CLINodeType::BEGIN ) )
{
    add_cmd( "show version", get_version );
    add_cmd( "show interfaces", get_interfaces );
    add_cmd( "show pppoe sessions", get_pppoe_sessions );
    add_cmd( "show aaa sessions", get_aaa_sessions );
}

void CLICMD::add_cmd( const std::string &full_command, cmd_callback callback ) {
    auto node = start_node;
    auto tokens = split( full_command );

    while( !tokens.empty() ) {
        auto ntoken = tokens.front();
        tokens.erase( tokens.begin() );

        if( auto nnode = std::find_if(
            node->next_nodes.begin(),
            node->next_nodes.end(),
            [ ntoken ]( const std::shared_ptr<CLINode> v ) -> bool {
                return v->token == ntoken;
            }
        ); nnode != node->next_nodes.end() ) {
            node = *nnode;
            continue;
        } else {
            node->next_nodes.push_back( std::make_shared<CLINode>( CLINodeType::STATIC, ntoken ) );
            node = node->next_nodes.back();
        }
    }
    node->next_nodes.push_back( std::make_shared<CLINode>( CLINodeType::STATIC, callback ) );
}

std::string CLICMD::call_cmd( const std::string &cmd ) {
    auto node = start_node;
    auto tokens = split( cmd );

    std::map<std::string,std::string> arguments;

    while( !tokens.empty() ) {
        auto ntoken = tokens.front();
        tokens.erase( tokens.begin() );
        std::cout << "Current token: " << ntoken << std::endl;

        if( auto nnode = std::find_if(
            node->next_nodes.begin(),
            node->next_nodes.end(),
            [ ntoken ]( const std::shared_ptr<CLINode> v ) -> bool {
                return v->token == ntoken;
            }
        ); nnode != node->next_nodes.end() ) {
            node = *nnode;
            continue;
        }
    }

    if( node->type != CLINodeType::END ) {
        throw std::runtime_error( "Wrong command" );
    }
    return node->callback( arguments );
}

CLIClient::CLIClient( boost::asio::io_context &i, const std::string &path ):
    io( i ),
    endpoint( path ),
    socket( i )
{
    socket.connect( endpoint );
    if( !socket.is_open() ) {
        throw std::runtime_error( "Can't connect to unix socket" );
    }
}

void CLIClient::process_input( const std::string &input ) {
    try {
        auto out = cmd.call_cmd( input ) + "\r\n\r\n";

        boost::asio::write( socket, boost::asio::buffer( out ) );
        std::string buf;
        auto n = boost::asio::read_until( socket, boost::asio::dynamic_buffer( buf ), "\r\n\r\n" );
        
        print_resp( buf );
    } catch( std::exception &e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void CLIClient::print_resp( const std::string &msg ) {
    auto result = deserialize<CLI_MSG>( msg );
    if( !result.error.empty() ) {
        std::cout << "Error: " << result.error << std::endl;
    }
    switch( result.cmd ) {
    case CLI_CMD::GET_PPPOE_SESSIONS: {
        auto resp = deserialize<GET_PPPOE_SESSION_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    }
    case CLI_CMD::GET_AAA_SESSIONS: {
        auto resp = deserialize<GET_AAA_SESSIONS_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    break;
    }
    case CLI_CMD::GET_VERSION: {
        auto resp = deserialize<GET_VERSION_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    }
    case CLI_CMD::GET_VPP_IFACES: {
        auto resp = deserialize<GET_VPP_IFACES_RESP>( result.data );
        std::cout << resp << std::endl;
        break;
    }
    }
}

int main( int argc, char *argv[] ) {
    std::cout << "Control utility of ppp control daemon" << std::endl;
    std::string cmd;

    try {
        boost::asio::io_context io;

        CLIClient cli { io, unix_socket_path };

        while( cmd != "exit" ) {
            std::cout << greeting;
            std::getline( std::cin, cmd );
            cli.process_input( cmd );
        }

    } catch( std::exception &e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}