#ifndef AAA_HPP_
#define AAA_HPP_

#include "auth_client.hpp"
#include "session.hpp"

struct AAAConf;

#define SESSION_ERROR UINT32_MAX

using aaa_callback = std::function<void(uint32_t,std::string)>;

class AuthClient;

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

    AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, std::function<void()> s );
    AAA_Session( const std::string &u, address_v4_t a, address_v4_t d1, address_v4_t d2, std::function<void()> s );
    ~AAA_Session();
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