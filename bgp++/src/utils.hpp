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

#endif