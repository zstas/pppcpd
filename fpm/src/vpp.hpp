#ifndef VPP_API_HPP_
#define VPP_API_HPP_

#include "vapi/vapi.hpp"
#include "vapi/vpe.api.vapi.hpp"
#include "vapi/ip.api.vapi.hpp"

struct VPPAPI {
    vapi::Connection con;
    VPPAPI();
    ~VPPAPI();

    bool work_route( fpm::Message &m, bool add );
    bool add_route( fpm::Message &m );
    bool del_route( fpm::Message &m );
};

#endif