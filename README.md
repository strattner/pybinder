## pybinder
A collection of Python scripts that enable management of DNS (BIND) using DDNS (RFC 2136). Uses the **dnspython** toolkit.

Built and tested using Python 3.5.2

Required modules (\* - part of standard library)

[dnspython](http://www.dnspython.org/)  *Does the heavy lifting in interacting with BIND*   
[docopt](https://github.com/docopt/docopt)  *Creates command line parser out of the program's comments; only needed if calling program directly*   
\* [ipaddress](https://docs.python.org/3/library/ipaddress.html)    
\* [logging](https://docs.python.org/3/library/logging.html)   
\* [re](https://docs.python.org/3/library/re.html)   

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

## managedns.py
Provides validation and additional modification functions (range).
```
./managedns.py --help
    ManageDNS

    Usage:
    managedns.py add_range [--debug <dfile>] [--server <server>] [--key <kfile>] [--fzone <fzone>]
                           [--rzone <rzone>] [--force] <start_name> <start_address> <num> [<index>]
    managedns.py -h|--help

    Arguments:
        start_name     FQDN or shortname for first entry
        start_address  IP address for first entry
        num            Number of entries to create

    Options:
        -h --help        Show this screen
        --debug <dfile>  Send debug logs to file
        --server <server>  Specify nameserver, if different from system default
        --key <kfile>      The TSIG key file containing name and hash
        --fzone <fzone>    The forward zone, if not obtainable from entry name
        --rzone <rzone>    The reverse zone, if not matching default from IP
        --force            Delete existing entries before adding new ones
        index              If not including in the start name, specify the index -
                           the starting value and number of digits to pad.
```
