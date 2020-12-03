#ifndef AAA_SESSION
#define AAA_SESSION

#include "auth_client.hpp"
#include "config.hpp"

using aaa_callback = std::function<void(uint32_t,std::string)>;

class AuthClient;
struct PPPOELocalTemplate;
struct RadiusResponse;

class AAA_Session : public std::enable_shared_from_this<AAA_Session> {
public:
    AAA_Session() = default;
    AAA_Session( const AAA_Session & ) = delete;
    AAA_Session( AAA_Session && ) = default;
    AAA_Session& operator=( const AAA_Session& ) = delete;
    AAA_Session& operator=( AAA_Session&& ) = default;

    AAA_Session( io_service &i, uint32_t sid, const std::string &u, const std::string &template_name );
    AAA_Session( io_service &i, uint32_t sid, const std::string &u, const std::string &template_name, RadiusResponse resp, std::shared_ptr<AuthClient> s );
    ~AAA_Session();

    uint32_t session_id;
    std::string username;
    address_v4_t address;
    address_v4_t dns1;
    address_v4_t dns2;
    std::string framed_pool;
    std::string vrf;
    std::string unnumbered;

    std::shared_ptr<AuthClient> acct { nullptr };
    bool free_ip { false };
    bool to_stop_acct{ false };

    void start();
    void stop();
    void on_started( RADIUS_CODE code, std::vector<uint8_t> pkt );
    void on_interim_answer( RADIUS_CODE code, std::vector<uint8_t> pkt );
    void on_stopped( RADIUS_CODE code, std::vector<uint8_t> pkt );
    void on_failed( std::string err );
    void on_interim( const boost::system::error_code& error );
    void map_iface( uint32_t ifi );

private:
    uint32_t ifindex;
    io_service &io;
    boost::asio::steady_timer timer;
};

#endif