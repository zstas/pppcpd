#include <boost/asio.hpp>
#include <iostream>
#include <queue>

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "fpm/fpm.pb.h"

#include "fpm.h"
#include "vpp.hpp"
#include "netlink.hpp"

extern void log( const std::string &m );