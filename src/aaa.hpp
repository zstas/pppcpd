#ifndef AAA_HPP_
#define AAA_HPP_

#define SESSION_ERROR UINT32_MAX

using aaa_callback = std::function<void(uint32_t,std::string)>;

enum class AAA_METHODS: uint8_t {
    NONE,
    LOCAL,
    RADIUS
};

struct FRAMED_POOL {
    address_v4_t start_ip;
    address_v4_t stop_ip;
    std::set<uint32_t> ips;

    FRAMED_POOL() = default;
    
    FRAMED_POOL( uint32_t sta, uint32_t sto ):
        start_ip( sta ),
        stop_ip( sto )
    {}

    FRAMED_POOL( std::string sta, std::string sto );

    uint32_t allocate_ip();
    void deallocate_ip( uint32_t i );
};

struct AAA_Session {
    std::string username;
    address_v4_t address;

    address_v4_t dns1;
    address_v4_t dns2;

    std::function<void(void)> on_stop;

    AAA_Session() = default;
    AAA_Session( const AAA_Session & ) = delete;
    AAA_Session( AAA_Session && ) = default;
    AAA_Session& operator=( const AAA_Session& ) = delete;
    AAA_Session& operator=( AAA_Session&& ) = default;

    AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, std::function<void()> s ):
        username( u ),
        address( a ),
        dns1( d1 ),
        on_stop( s )
    {}

    AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, address_v4_t d2, std::function<void()> s ):
        username( u ),
        address( a ),
        dns1( d1 ),
        dns2( d2 ),
        on_stop( s )
    {}

    ~AAA_Session() {
        if( on_stop != nullptr ) {
            on_stop();
        }
    }
};

struct PPPOELocalTemplate {
    std::string framed_pool;
    address_v4_t dns1;
    address_v4_t dns2;
};

struct AAARadConf {
    address_v4_t address;
    uint16_t port;
    std::string secret;

    AAARadConf() = default;

    AAARadConf( const std::string &a, uint16_t p, std::string s ):
        address( address_v4_t::from_string( a ) ),
        port( p ),
        secret( std::move( s ) )
    {}
};

struct AAAConf {
    std::vector<AAA_METHODS> method;
    std::map<std::string,FRAMED_POOL> pools;
    std::optional<PPPOELocalTemplate> local_template;
    std::vector<std::string> dictionaries;
    std::map<std::string,AAARadConf> auth_servers;
    std::map<std::string,AAARadConf> acct_servers;
};

class AAA {
    io_service &io;
    AAAConf &conf;
    std::map<uint32_t,AAA_Session> sessions;
    std::map<std::string,AuthClient> auth;
    std::map<std::string,AuthClient> acct;
    std::optional<RadiusDict> dict;

    // radius methods
    void startSessionRadius( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback );
    void startSessionRadiusChap( const std::string &user, const std::string &challenge, const std::string &response, PPPOESession &sess, aaa_callback callback );
    void processRadiusAnswer( aaa_callback callback, std::string user, RADIUS_CODE code, std::vector<uint8_t> v );
    void processRadiusError( aaa_callback callback, const std::string &error );
    // local and none methods
    std::tuple<uint32_t,std::string> startSessionNone( const std::string &user, const std::string &pass );

public:
    AAA( io_service &i, AAAConf &c );

    std::tuple<AAA_Session*,std::string> getSession( uint32_t sid );
    void startSession( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback );
    void startSessionCHAP( const std::string &user, const std::string &challenge, const std::string &response, PPPOESession &sess, aaa_callback callback );
    void stopSession( uint32_t sid );

};

#endif