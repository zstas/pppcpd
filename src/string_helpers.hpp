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
struct PacketPrint;
enum class PPPOE_CODE: uint8_t;
enum class PPP_PROTO : uint16_t;
struct PPPOESession;
enum class IfaceType: uint8_t;
struct VPPInterface;
struct VPPIfaceCounters;

// CLI types
struct GET_PPPOE_SESSION_RESP;
struct GET_VPP_IFACES_RESP;
struct GET_VERSION_RESP;
struct GET_AAA_SESSIONS_RESP;

using mac_t = std::array<uint8_t,6>;

std::ostream& operator<<( std::ostream &stream, const PPP_FSM_STATE &state );
std::ostream& operator<<( std::ostream &stream, const PPPOEDISC_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const ETHERNET_HDR &disc ); 
std::ostream& operator<<( std::ostream &stream, const RADIUS_CODE &code ); 
std::ostream& operator<<( std::ostream &stream, const RadiusPacket *pkt );
std::ostream& operator<<( std::ostream &stream, const pppoe_key_t &key );
std::ostream& operator<<( std::ostream &stream, const pppoe_conn_t &conn );
std::ostream& operator<<( std::ostream &stream, const mac_t &mac );
std::ostream& operator<<( std::ostream &stream, const PacketPrint &pkt );
std::ostream& operator<<( std::ostream &stream, const PPPOE_CODE &pkt );
std::ostream& operator<<( std::ostream &stream, const PPP_PROTO &pkt );
std::ostream& operator<<( std::ostream &stream, const PPPOESession &session );
std::ostream& operator<<( std::ostream &stream, const IfaceType &iface );
std::ostream& operator<<( std::ostream &stream, const VPPInterface &iface );
std::ostream& operator<<( std::ostream &stream, const VPPIfaceCounters &ctr );

std::ostream& operator<<( std::ostream &stream, const GET_PPPOE_SESSION_RESP &resp );
std::ostream& operator<<( std::ostream &stream, const GET_VPP_IFACES_RESP &resp );
std::ostream& operator<<( std::ostream &stream, const GET_VERSION_RESP &resp );
std::ostream& operator<<( std::ostream &stream, const GET_AAA_SESSIONS_RESP &resp );

#endif