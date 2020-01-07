#include "main.hpp"

std::tuple<std::vector<uint8_t>,std::string> ppp::processPPP( std::vector<uint8_t> pkt ) {
    std::vector<uint8_t> reply;
    reply.reserve( sizeof( ETHERNET_HDR ) + 128 );

    printHex( pkt );
    ETHERNET_HDR *eth = reinterpret_cast<ETHERNET_HDR*>( pkt.data() );
    log( "Ethernet packet:\n" + ether::to_string( eth ) );
    if( eth->ethertype != htons( ETH_PPPOE_SESSION ) ) {
        return { std::move( reply ), "Not pppoe session packet" };
    }

    return { std::move( reply ), "" };
}