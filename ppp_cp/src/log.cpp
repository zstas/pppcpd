#include "main.hpp"
#include <chrono>
#include <ctime>

void log( const std::string &msg ) {
    auto in_time_t = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() );

    std::cout << std::put_time( std::localtime( &in_time_t ), "%Y-%m-%d %X: ") << msg << std::endl;
}