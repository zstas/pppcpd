#include "main.hpp"

static std::string mac( const std::array<uint8_t,6> &mac ) {
    char buf[18] { 0 };
    snprintf( buf, sizeof( buf ), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    buf[ 17 ] = 0;
    return buf;
}

std::string ether::to_string( ETHERNET_HDR *eth ) {
    std::ostringstream out;
    out << "dst mac: ";
    for( auto const &el: eth->dst_mac) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out.seekp( -1, std::ios::end );
    out << std::endl;
    out << "src mac: ";
    for( auto const &el: eth->src_mac) {
        out << std::hex << std::setw( 2 ) << std::setfill('0') << (int)el << ":";
    }
    out.seekp( -1, std::ios::end );
    out << std::endl;
    out << "ethertype: 0x" << std::hex << std::setw(2) << htons( eth->ethertype ) << std::endl;

    return out.str();
}