#ifndef PACKET_HPP
#define PACKET_HPP

enum class RADIUS_CODE : uint8_t {
    ACCESS_REQUEST = 1,
    ACCESS_ACCEPT = 2,
    ACCESS_REJECT = 3,
    ACCOUNTING_REQUEST = 4,
    ACCOUNTING_RESPONSE = 5,
    ACCESS_CHALLENGE = 11,
    RESERVED = 255
};

namespace std {
    std::string to_string( const RADIUS_CODE &code );
}

struct RadiusPacket {
    RADIUS_CODE code;
    uint8_t id;
    BE16 length;
    authenticator_t authenticator;
}__attribute__((__packed__));

#endif