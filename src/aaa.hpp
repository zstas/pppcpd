#ifndef AAA_HPP_
#define AAA_HPP_

enum class AAA_METHODS: uint8_t {
    NONE,
    LOCAL,
    RADIUS
};

struct PPP_IPCONF {
    uint32_t address;
    uint32_t dns1;
    uint32_t dns2;
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

struct AAA {
    AAA_METHODS method { AAA_METHODS::NONE };
    IP_POOL pool1;
    std::map<std::string,PPP_IPCONF> confs;

    AAA( uint32_t s1, uint32_t s2, uint32_t d1, uint32_t d2 ):
        pool1( s1, s2, d1, d2 )
    {}

    bool startSession( const std::string &user, const std::string &pass ) {
        PPP_IPCONF conf;
        conf.address = pool1.allocate_ip();
        conf.dns1 = pool1.dns1;
        conf.dns2 = pool1.dns2;
        if( auto const &[ it, ret ] = confs.emplace( user, conf); !ret ) {
            return false;
        }
        return true;
    }

    std::tuple<PPP_IPCONF,std::string> getConf( const std::string &user ) {
        if( auto const &it = confs.find( user); it == confs.end() ) {
            return { PPP_IPCONF{}, "Cannot find user " + user };
        } else {
            return { it->second, "" };
        }
    }
};

#endif