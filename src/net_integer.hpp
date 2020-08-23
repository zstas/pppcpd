#ifndef NET_INTEGER_HPP
#define NET_INTEGER_HPP

constexpr auto bswap( uint16_t val ) noexcept {
    return __builtin_bswap16( val );
}

constexpr auto bswap( uint32_t val ) noexcept {
    return __builtin_bswap32( val );
}

template<typename T>
struct Raw {
    T value;
};

template<typename T>
Raw(T) -> Raw<T>;

template<typename T>
class NetInt {
    using Underlying = T;
    using Native = T;
public:
    constexpr NetInt() = default;

    constexpr explicit NetInt( Native v ) noexcept :
        value { bswap( v ) }
    {}

    constexpr explicit NetInt( Raw<Underlying> v ) noexcept :
        value { v.value }
    {}

    constexpr Native native() const {
        return bswap( value );
    }
    constexpr Underlying raw() const {
        return value;
    }

    constexpr NetInt& operator=( Native v ) {
        value = bswap( v );
        return *this;
    }

    friend std::ostream&
    operator<<(std::ostream& out, const NetInt& value) {
        return out << value.native();
    }

private:
    Underlying value;
}__attribute__((__packed__));

using BE16 = NetInt<uint16_t>;
using BE32 = NetInt<uint32_t>;

static_assert( sizeof( BE32 ) == 4, "BE32 is not 4 bytes long" );

#endif