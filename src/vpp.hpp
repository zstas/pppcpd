#ifndef VPP_API_HPP_
#define VPP_API_HPP_

#include "vapi/vapi.hpp"
#include "vapi/vpe.api.vapi.hpp"

#include "vapi/memclnt.api.vapi.hpp"

#include "config.hpp"

struct InterfaceConf;
enum class IfaceType: uint8_t;
struct VPPInterface;
struct VPP_PPPOE_Session;
struct VPPIfaceCounters;
struct VPPVRF;
struct VPPIP;
struct VPPUnnumbered;
struct PolicerInfo;

class VPPAPI {
public:
    VPPAPI( boost::asio::io_context &io, std::unique_ptr<Logger> &l );
    ~VPPAPI();

    // Interface dump methods
    std::set<uint32_t> get_tap_interfaces();
    std::vector<VPPInterface> get_ifaces();
    std::tuple<uint32_t,bool> get_iface_by_name( const std::string &name );
    void get_stats( uint32_t sw_if_index );

    // Subif
    std::tuple<bool,int32_t> add_subif( int32_t interface, uint16_t unit, uint16_t outer_vlan, uint16_t inner_vlan );
    bool del_subif( int32_t sw_if_index );

    // Tap
    std::tuple<bool,uint32_t> create_tap( const std::string &host_name );
    bool delete_tap( uint32_t id );

    // Interface configuration
    bool setup_interfaces( std::vector<InterfaceConf> ifaces );
    bool set_ip( uint32_t id, network_v4_t address, bool is_add = true );
    bool set_state( uint32_t ifi, bool admin_state );
    bool set_mtu( uint32_t ifi, uint16_t mtu );
    bool set_unnumbered( uint32_t unnumbered, uint32_t iface, bool is_add = true );
    bool set_interface_table( int32_t ifi, const std::string &vrf );
    std::vector<VPPIP> dump_ip( uint32_t id );
    std::vector<VPPUnnumbered> dump_unnumbered( uint32_t id );

    // Route methods
    std::tuple<bool,int32_t> add_route( const network_v4_t &prefix, const address_v4_t &nexthop, uint32_t table_id );

    // PPPoE methods
    std::tuple<bool,uint32_t> add_pppoe_session( uint32_t ip_address, uint16_t session_id, std::array<uint8_t,6> mac, const std::string &vrf, bool is_add = true );
    bool add_pppoe_cp( uint32_t sw_if_index, bool to_del = false );
    std::vector<VPP_PPPOE_Session> dump_pppoe_sessions();

    // VRF methods
    bool set_vrf( const std::string &name, uint32_t id, bool is_add = true );
    std::vector<VPPVRF> dump_vrfs();

    // Policer methods
    uint32_t policer_add_del( const std::string &name, uint32_t cir, uint64_t cb, bool isAdd = true );
    bool policer_input( const std::string &name, uint32_t sw_if_index, bool isAdd = true );
    bool policer_output( const std::string &name, uint32_t sw_if_index, bool isAdd = true );
    bool set_policer( uint32_t sw_if_index, const PolicerInfo& );
    void unset_policer( uint32_t sw_if_index );

    // Stats
    std::tuple<bool,VPPIfaceCounters> get_counters_by_index( uint32_t ifindex );
private:
    void collect_counters();

    void process_msgs( boost::system::error_code err );
    boost::asio::io_context &io;
    boost::asio::steady_timer timer;
    std::unique_ptr<Logger> &logger;
    std::map<uint32_t,VPPIfaceCounters> counters;
    std::map<std::string,uint32_t> vrfs;
    vapi::Connection con;
};

#endif
