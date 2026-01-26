# ltbgp
Not suitable for production! Minimal IPv6-only Linux BGP daemon. <br>
LTbgp is a very small BGP client, it was coded in around a week (without AI) based on RFC 4271, RFC 6793, RFC 1997, RFC 8092, RFC 4760, RFC 5492 and RFC 2385, with the main purpose being to understand how BGP works, so some code is suboptimal (config parser, message construction), and it may be buggy, and IS NOT RECOMMENDED TO BE USED IN PRODUCTION (or generally).<br>
Features:
- IPv6 (only)
- Advertising local routes
- Reloading the configuration without disrupting existing sessions, handles changed/removed/added routes
- Communities
- Large communities
- MD5 authentication
- Parsing UPDATEs, adding them to a local hashtable, and installing them to a local routing table based on very simplified and not RFC-compliant logic (the route with the highest localpref/as-path-length value is installed, for routes with the same value the route that was received first is installed)
- 32-bit ASNs (should work with both 16-bit and 32-bit neighbors)
- Prepending the local ASN
- Validation of remote BGP messages (RFC incompliant, only the general message format, AS_PATH, MP_REACH_NLRI and MP_UNREACH_NLRI are validated)

Not supported:
- IPv4
- Advertising any routes not in the local config (downstreaming)
- Querying local routes
- Incoming connections (it only initiates connections by itself, so security-wise there's a much smaller attack surface)
- Having multiple local ASNs
- Probably quite some other things as well

LTbgp can be started by running the binary without any arguments; to get the status, one can use `ltbgp status`, and to reload the config `ltbgp reload`. Logs are by default stored at `/etc/ltbgp/log`.
<br>
The config format is rather simple, currently ltbgp expects the config to be at /etc/ltbgp/config, there are global config values, neighbor-specific config values, group-specific config values, and routes. Lines are ignored if they start with a '#'. For details, you may look at config.c.

Example config:
```
status_port 999
log /etc/ltbgp/log
pid /etc/ltbgp/pid
table 150
id 1.1.1.1
asn 202986
neighbor upstream
.hold_time 30
.routelimit 500000
.multihop 2
.localpref 100
.interface eno1
.local_ip 2a03:XXXX
.gateway 2a03:XXXX
.only_default_route false
.remote_asn 56655
.remote_ip 2a03:XXXX
group anycast
@upstream 2 1299:7009 1299:5009 1299:10050 56655:310 56655:310 56655:311 56655:312
route 2a14:7580:f100::/48 anycast
route 2a14:7580:f101::/48 default
```
