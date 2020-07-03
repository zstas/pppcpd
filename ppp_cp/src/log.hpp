#include <iostream>

enum class LOGL: uint8_t {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    ALERT
};

enum class LOGS: uint8_t {
    MAIN,
    PPPOED,
    PPP,
    LCP,
    IPCP,
    PPP_AUTH,
    AAA
};

std::ostream& operator<<( std::ostream &os, const LOGL &l );

class Logger {
private:
    std::ostream &os;
    LOGL minimum;
    bool noop;
    using endl_type = decltype( std::endl<char, std::char_traits<char>> );

    Logger& printTime( const LOGL &level ) {
        auto in_time_t = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() );
        *this << std::put_time( std::localtime( &in_time_t ), "%Y-%m-%d %X: ") << level;
        return *this;
    }

public:
    Logger( std::ostream &o = std::cout ):
        os( o ),
        minimum( LOGL::INFO ),
        noop( false )
    {}

    void setLevel( const LOGL &level ) {
        minimum = level;
    }

    // template<typename T>
    // Logger& operator<<( endl_type endl ) {
    //     noop = false;
    //     return *this;
    // }

    Logger& operator<<( std::ostream& (*fun)( std::ostream& ) ) {
        if( !noop ) {
            os << std::endl;
        }
        noop = false;
        return *this;
    }

    template<typename T>
    Logger& operator<<( const T& data ) {
        if( !noop ) {
            os << data;
        }
        return *this;
    }

    Logger& logInfo() {
        if( minimum > LOGL::INFO ) {
            noop = true;
        }
        return printTime( LOGL::INFO );
    }

    Logger& logDebug() {
        if( minimum > LOGL::DEBUG ) {
            noop = true;
        }
        return printTime( LOGL::DEBUG );
    }

    Logger& logAlert() {
        if( minimum > LOGL::ALERT ) {
            noop = true;
        }
        return printTime( LOGL::ALERT );
    }
};

void log( const std::string &msg );