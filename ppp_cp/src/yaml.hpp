#ifndef YAML_HPP
#define YAML_HPP

#include <yaml-cpp/yaml.h>

namespace YAML {
    template <>
    struct convert<PPPOEPolicy>
    {
        static Node encode(const PPPOEPolicy &rhs);
        static bool decode(const Node &node, PPPOEPolicy &rhs);
    };

    template <>
    struct convert<FRAMED_POOL>
    {
        static Node encode(const FRAMED_POOL &rhs);
        static bool decode(const Node &node, FRAMED_POOL &rhs);
    };

    template <>
    struct convert<AAA_METHODS>
    {
        static Node encode(const AAA_METHODS &rhs);
        static bool decode(const Node &node, AAA_METHODS &rhs);
    };

    template <>
    struct convert<AAA>
    {
        static Node encode(const AAA &rhs);
        static bool decode(const Node &node, AAA &rhs);
    };
}

#endif
