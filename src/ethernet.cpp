#include "main.hpp"

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