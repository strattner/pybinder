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
