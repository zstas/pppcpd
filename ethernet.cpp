#include "main.hpp"

EthernetHeader::EthernetHeader( std::vector<uint8_t> pkt ) {
    std::copy( pkt.begin(), pkt.begin() + 6, dst_mac.begin() );
    std::copy( pkt.begin() + 6, pkt.begin() + 12, src_mac.begin() );
    ethertype = *reinterpret_cast<uint16_t *>( &pkt.at( 12 ) );
}

static std::string mac( const std::array<uint8_t,6> &mac ) {
    char buf[18] { 0 };
    snprintf( buf, sizeof( buf ), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
    buf[ 17 ] = 0;
    return buf;
}

std::string EthernetHeader::toString() const {
    std::ostringstream out;
    out << "dst mac: " << mac( dst_mac ) << std::endl;
    out << "src mac: " << mac( src_mac ) << std::endl;
    out << "ethertype: " << std::to_string( ethertype ) << std::endl;

    return out.str();
}