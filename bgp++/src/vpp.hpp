#ifndef VPP_API_HPP_
#define VPP_API_HPP_

#include "vapi/vapi.hpp"
#include "vapi/vpe.api.vapi.hpp"

#include "vapi/session.api.vapi.hpp"

struct vpp_api {
    vapi::Connection con;
    vpp_api();
    ~vpp_api();

    bool attach_application();
    int32_t bind( uint16_t port );
    int32_t accept();
};

#endif