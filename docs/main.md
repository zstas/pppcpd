## Documentation ##
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
In general there are 2 steps to setup a PPPoE Session:
* PPPoE establishing between subcriber and AC
* PPP protocols negotiation: LCP/IPCP/CHAP/PAP
