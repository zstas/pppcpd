## Description ##
This is repo of my NFV experiments with VPP. You can read about them on my [blog](https://zstas.github.io).

Now there are just 2 daemons, both written in modern C++ with ASIO.

### PPP Control Plane Daemon ###
Half-way working daemon which can establish PPPoE sessions and install them into VPP (though API).

### FIB Manager ###
WIP. This daemon will be installing routes from FRR through FPM (Zebra FIB Push Manager).