# PPP Control Plane Daemon #
This is the control plane for PPPoE plugin for VPP.

## Features ##
* Ethernet or VLAN encapsulation
* PPPoE: service name filtering, AC cookie
* PPP: LCP, IPCP, PAP
* AAA: RADIUS authentication, no authentication

## Dependencies ##
* VPP
* cmake, gcc

## How to install ##
```
cd pppcpd/
mkdir build
cd build/
cmake -DCMAKE_BUILD_TYPE=DEBUG -DBUILD_TESTING=OFF ..
```