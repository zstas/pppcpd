#ifndef UTILS_H_
#define UTILS_H_

enum class LOG_APP {
    APPLICATION,
    FSM,
    CONNECTION,
    CONFIGURATION,
};

void log( const std::string &msg );
void log( const LOG_APP &app, const std::string &msg );
uint16_t bswap16( uint16_t value ) noexcept;
uint32_t bswap32( uint32_t value ) noexcept;

#endif