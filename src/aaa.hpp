#ifndef AAA_HPP_
#define AAA_HPP_

#define SESSION_ERROR UINT32_MAX

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
    uint32_t address;

    uint32_t dns1;
    uint32_t dns2;

    AAA_Session() = default;
    AAA_Session( const AAA_Session & ) = default;
    AAA_Session( AAA_Session && ) = default;
    AAA_Session& operator=( const AAA_Session& ) = default;
    AAA_Session& operator=( AAA_Session&& ) = default;

    AAA_Session( const std::string &u, uint32_t a, IP_POOL &p ):
        username( u ),
        address( a ),
        dns1( p.dns1 ),
        dns2( p.dns2 )
    {}
};

struct AAA {
    AAA_METHODS method { AAA_METHODS::NONE };
    IP_POOL pool1;
    std::map<uint32_t,AAA_Session> sessions;

    AAA( uint32_t s1, uint32_t s2, uint32_t d1, uint32_t d2 ):
        pool1( s1, s2, d1, d2 )
    {}

    std::tuple<AAA_Session,std::string> getSession( uint32_t sid );
    std::tuple<uint32_t,std::string> startSession( const std::string &user, const std::string &pass );
    std::string dp_provision( uint32_t sid );
};

#endif