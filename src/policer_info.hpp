#ifndef SRC_POLICER_INFO_HPP
#define SRC_POLICER_INFO_HPP

#include <cstdint>
#include <string>

struct PolicerInfo {
  PolicerInfo( const std::string& );

  uint32_t rate_in;
  uint32_t burst_in;
  
  uint32_t rate_out;
  uint32_t burst_out;
};

#endif
