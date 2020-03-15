project('bgp++', 'cpp', default_options : ['cpp_std=c++17'])
pthread = dependency('threads')
boost = dependency('boost', modules:[ 'system' ])
executable('bgpd', 'src/main.cpp', dependencies : [ boost, pthread ] )