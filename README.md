## pybinder
A collection of Python scripts that enable management of DNS (BIND) using DDNS (RFC 2136). Uses the **dnspython** toolkit.

Required modules
[dnspython](http://www.dnspython.org/)

## searchdns.py
Will perform a search of one or more records (by name or IP), to the nameserver specified (or use system default).
```
./searchdns.py --help
    SearchDNS.

    Usage:
           searchdns.py [--server <server>] [--domain <domain>] [--debug <file>] <query>...
           searchdns.py -h | --help

    Arguments:
        query                   One or more names or IPs to search

    Options:
        -h --help               Show this screen
        --server <server>       Specify the nameserver (if not system default)
        --domain <domain>       Specify the search domain (if FQDN is not given)
        --debug <file>          Send debug messages to a file
```

## modifydns.py
Will perform modification of DNS, with no validation (checking if entry already exists).
```
./modifydns.py --help
    ModifyDNS

    Usage:
        modifydns.py add_forward [--debug <dfile>] [--server <server>] [--key <kfile>]
                                 [--zone <zone>] <name> <address>...
        modifydns.py add_reverse [--debug <dfile>] [--server <server>] [--key <kfile>]
                                 [--zone <zone>] <address> <name>
        modifydns.py add_alias [--debug <dfile>] [--server <server>] [--key <kfile>]
                               [--zone <zone>] <alias> <name>
        modifydns.py delete_forward [--debug <dfile>] [--server <server>] [--key <kfile>]
                                 [--zone <zone>] <name>
        modifydns.py delete_reverse [--debug <dfile>] [--server <server>] [--key <kfile>]
                                 [--zone <zone>] <address>
        modifydns.py delete_alias [--debug <dfile>] [--server <server>] [--key <kfile>]
                               [--zone <zone>] <alias>
        modifydns.py -h | --help

    Arguments:
        name        FQDN or shortname (if zone can be determined)
        address     IP address
        alias       FQDN or shortname (if zone can be determined)

    Options:
        -h --help        Show this screen
        --debug <file>     Send debug logs to file
        --server <server>  Specify nameserver, if different from system default
        --key <kfile>      The TSIG key file containing name and hash
        --zone <zone>      Forward or reverse zone, if overriding name/address zone
```
