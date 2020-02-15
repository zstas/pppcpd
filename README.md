## Description ##
This is a repo of my NFV experiments with VPP. You can read about them in my [blog](https://zstas.github.io).

Now there are just 2 daemons, both written in modern C++ with ASIO.

If you want to participate in any way, you can find my contacts in my blog.

### PPP Control Plane Daemon ###
Almost working daemon which can establish PPPoE sessions and install them into VPP (through API). It is the first step to my idea of writing an open-sourced vBNG.

### FIB Manager ###
WIP. This daemon will be installing routes from FRR through FPM (Zebra FIB Push Manager). At this point, I'm trying to support just Protobuf but in the future, I'm planning to add Netlink mode.