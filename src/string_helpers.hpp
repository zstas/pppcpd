#ifndef STRING_HELPERS_HPP_
#define STRING_HELPERS_HPP_

#include <iosfwd>

class pppoe_key_t;
class pppoe_conn_t;
enum class PPP_FSM_STATE: uint8_t;
struct PPPOEDISC_HDR;
struct ETHERNET_HDR;
enum class RADIUS_CODE : uint8_t;
struct RadiusPacket;

std::ostream& operator<<( std::ostream &stream, const PPP_FSM_STATE &state );
std::ostream& operator<<( std::ostream &stream, const PPPOEDISC_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const ETHERNET_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const RADIUS_CODE &code ); 
std::ostream& operator<<( std::ostream &stream, const RadiusPacket *pkt );
std::ostream& operator<<( std::ostream &stream, const pppoe_key_t &key );
std::ostream& operator<<( std::ostream &stream, const pppoe_conn_t &conn );

#endif