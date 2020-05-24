#ifndef AAA_HPP_
#define AAA_HPP_

#define SESSION_ERROR UINT32_MAX

using aaa_callback = std::function<void(uint32_t,std::string)>;

enum class AAA_METHODS: uint8_t {
    NONE,
    LOCAL,
    RADIUS
};

struct IP_POOL {
    uint32_t start_ip;
    uint32_t stop_ip;
    uint32_t dns1;
    uint32_t dns2;
    std::set<uint32_t> ips;

    IP_POOL() = default;
    
    IP_POOL( uint32_t sta, uint32_t sto, uint32_t d1, uint32_t d2 ):
        start_ip( sta ),
        stop_ip( sto ),
        dns1( d1 ),
        dns2( d2 )
    {}

    uint32_t allocate_ip() {
        for( uint32_t i = start_ip; i <= stop_ip; i++ ) {
            if( const auto &iIt = ips.find( i ); iIt == ips.end() ) {
                ips.emplace( i );
                return i;
            }
        }
        return 0;
    }

    void deallocate_ip( uint32_t i ) {
        if( const auto &iIt = ips.find( i ); iIt != ips.end() ) {
            ips.erase( iIt );
        }
    }
};

struct AAA_Session {
    std::string username;
    address_v4 address;

    address_v4 dns1;
    address_v4 dns2;

    AAA_Session() = default;
    AAA_Session( const AAA_Session & ) = default;
    AAA_Session( AAA_Session && ) = default;
    AAA_Session& operator=( const AAA_Session& ) = default;
    AAA_Session& operator=( AAA_Session&& ) = default;

    AAA_Session( const std::string &u, address_v4 a, address_v4 d1 ):
        username( u ),
        address( a ),
        dns1( d1 )
    {}

    AAA_Session( const std::string &u, address_v4 a, address_v4 d1, address_v4 d2 ):
        username( u ),
        address( a ),
        dns1( d1 ),
        dns2( d2 )
    {}
};

struct AAA {
    std::set<AAA_METHODS> method;
    IP_POOL pool1;
    std::map<uint32_t,AAA_Session> sessions;
    std::map<uint8_t,AuthClient> auth;
    std::optional<RadiusDict> dict;

    AAA( uint32_t s1, uint32_t s2, uint32_t d1, uint32_t d2 ):
        pool1( s1, s2, d1, d2 )
    {
        method.emplace( AAA_METHODS::NONE );
    }

    AAA ( io_service &io, address_v4 radius_ip, uint16_t port, const std::string secret, RadiusDict d ):
        dict( std::move( d ) )
    {
        method.emplace( AAA_METHODS::RADIUS );
        auth.emplace( std::piecewise_construct, std::forward_as_tuple( 0 ), std::forward_as_tuple( io, radius_ip, port, secret, *dict ) );
    }

    std::string addRadiusAuth( io_service &io, std::string server_ip, uint16_t port, const std::string secret, const std::vector<std::string> paths_to_dict );

    std::tuple<AAA_Session,std::string> getSession( uint32_t sid );
    void startSession( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback );
    std::tuple<uint32_t,std::string> startSessionNone( const std::string &user, const std::string &pass );
    void startSessionRadius( const std::string &user, const std::string &pass, PPPOESession &sess, aaa_callback callback );
    std::string dp_provision( uint32_t sid );
    void processRadiusAnswer( aaa_callback callback, std::string user, std::vector<uint8_t> v );

    void changeAuthMethods( std::initializer_list<AAA_METHODS> m );

};

#endif