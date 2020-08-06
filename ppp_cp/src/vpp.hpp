#ifndef VPP_API_HPP_
#define VPP_API_HPP_

#include "vapi/vapi.hpp"
#include "vapi/vpe.api.vapi.hpp"

#include "vapi/interface.api.vapi.hpp"
#include "vapi/tapv2.api.vapi.hpp"
#include "vapi/pppoe.api.vapi.hpp"

enum class IfaceType: uint8_t {
    LOOPBACK,
    HW_IFACE,
    TAP
};

struct VPPInterface {
    std::string name;
    std::string device;
    mac_t mac;
    uint32_t sw_if_index;
    uint32_t speed;
    uint16_t mtu;
    IfaceType type;
};

std::ostream& operator<<( std::ostream &stream, const IfaceType &iface );
std::ostream& operator<<( std::ostream &stream, const struct VPPInterface &iface );

class VPPAPI {
public:
    VPPAPI( boost::asio::io_context &io, std::unique_ptr<Logger> &l );

    ~VPPAPI();

    bool add_pppoe_session( uint32_t ip_address, uint16_t session_id, std::array<uint8_t,6> mac, bool is_add = true );
    bool add_subif( uint32_t iface, uint16_t outer_vlan, uint16_t inner_vlan );
    std::tuple<bool,uint32_t> create_tap( const std::string &host_name );
    bool delete_tap( uint32_t id );
    std::set<uint32_t> get_tap_interfaces();
    std::vector<VPPInterface> get_ifaces();
    bool set_ip( uint32_t id, network_v4_t address );
    bool set_state( uint32_t ifi, bool admin_state );
private:
    void process_msgs( boost::system::error_code err );
    boost::asio::io_context &io;
    boost::asio::steady_timer timer;
    std::unique_ptr<Logger> &logger;
    vapi::Connection con;
};

#endif