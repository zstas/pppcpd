## Documentation ##
### Installation ###
0. Installing dependecies:
```
sudo apt install -y git
sudo apt install -y cmake
sudo apt install -y g++ gcc
sudo apt install -y libboost1.74-all-dev
```
1. Installing VPP:
```
git clone https://gerrit.fd.io/r/vpp.git
cd vpp
make install-dep
make install-ext-dep
make build
make pkg-deb-debug
cd build-root/
sudo dpkg -i *.deb 
sudo apt install --fix-broken
```
2. Installing PPPCPD:
```
cd pppcpd/
mkdir build
cd build/
cmake -DCMAKE_BUILD_TYPE=DEBUG -DBUILD_TESTING=OFF ..
```

3. systemd service unit example:
```
/lib/systemd/system/pppcpd.service 
[Unit]
Description=PPPoE Control Plane Daemon
After=vpp.service

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=/home/dataf/pppcpd/build/pppcpd -p /home/dataf/pppcpd/build/config.yaml
StandardOutput=syslog
StandardError=syslog
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

### Configuration ###
You can generate a sample configuration running a pppcpd with -g:
```
./pppcpd -g
```

By default PPPCPD will look for `config.yaml` in the current directory. But you can pass certain path with `-p` option:

```
./pppcpd -p /etc/pppcpd/pppd.yaml
```

The configuration should be written in YAML format. Let's have a look at this sample configuration:

```
tap_name: tap0
```
This is the name of tap interface, that will be created to pass packets between VPP and PPPCPD. Just make sure that is unique name for the interface.

```
interfaces:
  - device: GigabitEthernet0/8/0
    admin_state: true
    mtu: 1500
    units:
      200:
        admin_state: true
        vlan: 200
      201:
        admin_state: true
        vlan: 201
      202:
        admin_state: true
        vlan: 202
  - device: GigabitEthernet0/9/0
    admin_state: true
    mtu: 1500
    units:
      150:
        admin_state: true
        address: 10.0.0.2/24
        vlan: 150
      250:
        admin_state: true
        address: 10.10.0.2/24
        vlan: 250
        vrf: RED
```
Configuration for the interfaces. Units just the same thing as subinterface. So you can specify vlan, IP address and VRF for them. Name should be an unique number (can be same as vlan).

```
default_pppoe_conf:
  ac_name: vBNG AC PPPoE
  service_name:
    - inet
    - pppoe
  insert_cookie: true
  ignore_service_name: true
```
Default PPPoE configuration. This config is made for interacting when establish PPPoE Session - to filter services and other misc configuration (like AC name, inserting cookie, etc).

```
pppoe_confs:
  150:
    ac_name: vBNG AC PPPoE
    service_name:
      []
    insert_cookie: true
    ignore_service_name: true
  250:
    ac_name: vBNG AC PPPoE
    service_name:
      - iptv
    insert_cookie: true
    ignore_service_name: false
```
Just as previous but specified for certain VLAN.

```
pppoe_templates:
  template1:
    framed_pool: pppoe_pool1
    dns1: 8.8.8.8
    dns2: 1.1.1.1
    unnumbered: GigabitEthernet0/9/0.150
  template2:
    framed_pool: vrf_pool1
    dns1: 8.8.8.8
    dns2: 1.1.1.1
    vrf: RED
    unnumbered: GigabitEthernet0/9/0.250
```
Templates are used for configuring actual PPPoE Session. If there are information from RADIUS answer, then it will be applied. If not, information will be applied from template.


```
aaa_conf:
  pools:
    pppoe_pool1:
      start_ip: 100.64.0.10
      stop_ip: 100.64.255.255
    vrf_pool1:
      start_ip: 100.66.0.10
      stop_ip: 100.66.0.255
  method:
    - RADIUS
    - NONE
  local_template: template1
  dictionaries:
    - /usr/share/freeradius/dictionary.rfc2865
    - /usr/share/freeradius/dictionary.rfc2866
    - /usr/share/freeradius/dictionary.rfc2869
    - /usr/share/freeradius/dictionary.ericsson.ab
  auth_servers:
    main_auth_1:
      address: 127.0.0.1
      port: 1812
      secret: testing123
  acct_servers:
    main_acct_1:
      address: 127.0.0.1
      port: 1813
      secret: testing123
```
AAA configuration, there we have IP pools (just ipv4 for now), methods (radius/none) and in what order they should work (e.g. in case when RADIUS server doesn't respond, none authentication will be applied).
And then actual RADIUS servers for authentication and accounting. You should provide proper paths for the RADIUS dictionaries.

```
global_rib:
  entries:
    - destination: 0.0.0.0/0
      nexthop: 10.0.0.1
      description: default gateway
```
This is just static route configuration. These static routes will be configured on startup.

```
vrfs:
  - name: RED
    table_id: 10
    rib:
      entries:
        - destination: 0.0.0.0/0
          nexthop: 10.10.0.1
          description: default gateway
```
VRF are specified here. You should allocate unique table_id for every VRF. Also, we have a static routing table for every VRF, just the same as global RIB setting.

### Sesssion establishing ###
In summary, there are 2 steps to setup a PPPoE Session:
* PPPoE establishing between subcriber and AC
* PPP protocols negotiation: LCP/IPCP/CHAP/PAP

In details:

1. PPPoE AC answers regarding with PPPOEPolicy to requests from users. PPPOEPolicy is selected by vlan (or stay default).
2. Established PPPoE session is stored in runtime. PPP protocols negotiation is started. PPPCPD uses separate FSM for every PPP protocol.
3. PPP LCP negotiated with honouring LCPPolicy. For now LCP policy is hardcoded, but it can easily be removed to the global configuration.
4. Then, PPP PAP or CHAP negotiation is started. On that stage AAA session started, it may be RADIUS or NOAUTH session for now. All information received from RADIUS and PPPOETemplate is stored in AAA session. AAA session is bound to PPPOESession.
5. Finally, PPP IPCP negotiation is started with settings from previous step. On that stage VPP is being programmed: creating PPPoE session in dataplane, applying IP settings, etc.
6. Periodic updates are being started at this moment. If the subscriber doesn't answer LCP Echo requests, both AAA and PPPOESession are stopped. 

### Applying IP settings ###
Depending on AAA settings we could have different entitites to confgure IP Address. They are listed in order of priority:
* `Framed-IP-Address` from RADIUS response
* `Framed-Pool` from RADIUS response
* Framed-Pool setting from PPPOETemplate

In case of NOAUTH we have only last option. 

DNS are applied:
* `Client-DNS-Pri` and `Client-DNS-Sec` from Ericsson RADIUS dictionary
* DNS1 and DNS2 settings from PPPOETemplate

IP Unnumbered is applied only from PPPOETemplate.

VRF is also applied from PPPOETemplate.

### Reloading configuration ###
Configuration from YAML file specified in `-p` option is processed on SIGHUP. For now, only policies are updated. Entities such VPP interfaces and routes aren't being updated during this process. 

### Troubleshooting ###
* Logs are redirected to syslog.
* Capturing packets on CP interface, usually `tap0` with tcpdump/wireshark.
* RADIUS packets are sent via regular system interfaces (not through VPP).
* Since only static routes are supported, it's easy to tshoot ip routing issues, see below.

Tshooting VPP:

`show ip fib [table <x>] [x.x.x.x/y]` - to check IP routing table 

`show pppoe session` - to check programmed session in VPP.

`show pppoe fib` - to see interfaces and mac addresses of pppoe users.

`show ip neigh` - to check arp/nd state

`show interface [addr]` - to see actual hw and sw interfaces and addresses on them.