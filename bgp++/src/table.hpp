#ifndef TABLE_HPP_
#define TABLE_HPP_

#include "packet.hpp"

struct bgp_table_v4 {
    std::map<prefix_v4,std::shared_ptr<path_attr_t>> table;
};

#endif