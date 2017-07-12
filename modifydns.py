#!/usr/bin/python3
"""
 modifydns

 Author: Scott Strattner (sstrattn@us.ibm.com)

 Copyright (c) 2017 IBM Corp.
 All Rights Reserved

"""

import re
import logging
import ipaddress
import dns.query
import dns.tsigkeyring
import dns.update
import dns.rdatatype
import dns.reversename
from searchdns import SearchDNS, DNSSearchAnswer


class DNSModifyError(Exception):  # pylint: disable=missing-docstring
    NO_ZONE = "No zone specififed"


class DNSModifyRequest(object):  # pylint: disable=too-few-public-methods
    """
    Encapsulates a DNS request. Should include the value, even if it is
    a delete request, so that the action can be undone if needed.
    """

    ADD = "Add"
    DELETE = "Delete"
    ACTIONS = [ADD, DELETE]

    def __init__(self, action, rtype, entry, value):
        self.action = action if action in self.ACTIONS else None
        self.rtype = rtype
        self.entry = entry
        self.value = value

    def __str__(self):
        fmt_str = "{} {} record for entry {}"
        return_string = fmt_str.format(self.action, dns.rdatatype.to_text(self.rtype), self.entry)
        if self.value:
            return_string += " with value {}".format(self.value)
        return return_string

    def reverse_request(self):
        """
        To support an undo operation, reverse the request and create a
        new DNSModifyRequest instance.
        """
        if not self.action:
            return None
        if self.action == self.ADD:
            return DNSModifyRequest(self.DELETE, self.rtype, self.entry, self.value)
        return DNSModifyRequest(self.ADD, self.rtype, self.entry, self.value)


class DNSModifyAnswer(object):  # pylint: disable=too-few-public-methods
    """
    Provides a simple interface to dns.message.Message, which
    is returned when performing an add/delete call to DNS.
    """

    # The return codes come from BIND, except for 99, which is used when
    # a delete request is made for an entry that does not exist in DNS.

    CANCEL_REQUEST = 99

    RETURN_CODE = {0: "completed successfully",
                   2: "failed with a server failure",
                   3: "failed as domain was not found",
                   5: "failed as request was refused",
                   9: "failed as not authorized to perform the request",
                   10: "failed as improper zone was given",
                   CANCEL_REQUEST: "canceled as entry does not exist"}

    def __init__(self, request, dns_message):
        self.request = request
        self.rcode = dns_message

    def __str__(self):
        return_string = str(self.request) + ": " + self.RETURN_CODE[self.rcode]
        return return_string


class ModifyDNS(object):
    """
    Perform atomic DNS add and delete actions.
    """

    TTL = 86400

    def __init__(  # pylint: disable=too-many-arguments
            self,
            nameserver=None,
            forward_zone=None,
            reverse_zone=None,
            ttl=None,
            key_name=None,
            key_hash=None):
        self.nameserver = nameserver
        self.forward_zone = forward_zone
        self.reverse_zone = reverse_zone
        self.forward_search = SearchDNS(self.nameserver, self.forward_zone)
        self.reverse_search = SearchDNS(self.nameserver, self.reverse_zone)
        self.ttl = ttl if ttl else self.TTL
        if key_name and key_hash:
            self.keyring = dns.tsigkeyring.from_text({key_name: key_hash})
        else:
            self.keyring = None
        self.__print_attributes()

    def __print_attributes(self):
        logging.debug("%s", self.__dict__)

    def _get_name_and_zone(self, name):
        if '.' in name:
            (shortname, zone) = name.split('.', 1)
        else:
            shortname = name
            if self.forward_zone:
                zone = self.forward_zone
            else:
                logging.debug("Unable to find zone for %s", name)
                raise DNSModifyError(DNSModifyError.NO_ZONE)
        return (shortname, zone)

    def __get_rev_name_and_zone(self, address):
        logging.debug("Address %s type is %s", address, address.__class__)
        zone = self.reverse_zone
        revname = dns.reversename.from_address(address)
        if not zone:  # Without a given reverse zone, the assumption is that the zone
            # is at the "class C" aka /24 boundary
            try:
                network_address = ipaddress.ip_network(address + '/24', False)
                logging.debug("Found network address %s for reverse zone calculation", str(network_address))
                rev_network_addr = str(
                    dns.reversename.from_address(str(network_address.network_address)))
                last_octet_index = rev_network_addr.find('.')
                zone = rev_network_addr[last_octet_index:]
            except ValueError:
                logging.debug("Unable to find reverse zone for %s", address)
                raise DNSModifyError(DNSModifyError.NO_ZONE)
        return (revname, zone)

    def add_forward(self, name, address):
        """
        Create A record. Does not check if name is already in use.
        Does not verify that address is an actual IP address.
        Because round-robin entries are supported, returns an array
        of DNSModifyAnswers.
        """
        answer = []
        logging.debug("Forward add request for %s %s", name, address)
        shortname, zone = self._get_name_and_zone(name)
        update = dns.update.Update(zone, keyring=self.keyring)
        if not isinstance(address, list):
            address = [address]
        for addr in address:
            request = DNSModifyRequest(DNSModifyRequest.ADD, dns.rdatatype.A, name, addr)
            update.add(shortname, self.ttl, dns.rdatatype.A, addr)
            result = dns.query.tcp(update, self.nameserver)
            logging.debug("Adding forward record result: %s", result)
            answer.append(DNSModifyAnswer(request, result.rcode()))
        return answer

    def add_reverse(self, address, name):
        """
        Create PTR record. Does not check if address is already in use.
        """
        request = DNSModifyRequest(DNSModifyRequest.ADD, dns.rdatatype.PTR, address, name)
        logging.debug("Reverse add request for %s %s", address, name)
        reverse_name, zone = self.__get_rev_name_and_zone(address)
        shortname, fzone = self._get_name_and_zone(name)
        fqdn = shortname + '.' + fzone
        if not fqdn.endswith('.'):
            fqdn += '.'
        update = dns.update.Update(zone, keyring=self.keyring)
        update.add(reverse_name, self.ttl, dns.rdatatype.PTR, fqdn)
        result = dns.query.tcp(update, self.nameserver)
        logging.debug("Adding reverse record result: %s", result)
        return DNSModifyAnswer(request, result.rcode())

    def add_alias(self, cname, rname):
        """
        Create CNAME record. Does not check if cname is already in use, or if
        rname exists.
        """
        request = DNSModifyRequest(DNSModifyRequest.ADD, dns.rdatatype.CNAME, cname, rname)
        logging.debug("Alias add request for %s pointing to %s", cname, rname)
        cshort, czone = self._get_name_and_zone(cname)
        rshort, rzone = self._get_name_and_zone(rname)
        rfqdn = rshort + '.' + rzone
        if not rfqdn.endswith('.'):
            rfqdn += '.'
        update = dns.update.Update(czone, keyring=self.keyring)
        update.add(cshort, self.ttl, dns.rdatatype.CNAME, rfqdn)
        result = dns.query.tcp(update, self.nameserver)
        logging.debug("Adding alias record result: %s", result)
        return DNSModifyAnswer(request, result.rcode())

    def delete_forward(self, name, addr=None):
        """
        Delete an A record. If 'addr' is not provided, the record will be searched for.
        """
        if not addr:
            existing = self.forward_search.query(name)
            if existing.type == DNSSearchAnswer.NOT_FOUND:
                request = DNSModifyRequest(DNSModifyRequest.DELETE, dns.rdatatype.A, name, None)
                return DNSModifyAnswer(request, DNSModifyAnswer.CANCEL_REQUEST)
            addr = existing.addr
        request = DNSModifyRequest(DNSModifyRequest.DELETE, dns.rdatatype.A, name, addr)
        logging.debug("Forward delete request for %s with existing value %s", name, addr)
        shortname, zone = self._get_name_and_zone(name)
        update = dns.update.Update(zone, keyring=self.keyring)
        update.delete(shortname, dns.rdatatype.A)
        result = dns.query.tcp(update, self.nameserver)
        logging.debug("Deleting forward record result: %s", result)
        return DNSModifyAnswer(request, result.rcode())

    def delete_reverse(self, address, name=None):
        """
        Delete a PTR record. If 'name' is not provided, the record will be searched for.
        """
        logging.debug("Address %s type is %s", address, address.__class__)
        if not name:
            existing = self.reverse_search.query(address)
            if existing.type == DNSSearchAnswer.NOT_FOUND:
                request = DNSModifyRequest(DNSModifyRequest.DELETE, dns.rdatatype.PTR, address, None)
                return DNSModifyAnswer(request, DNSModifyAnswer.CANCEL_REQUEST)
            name = existing.name
        request = DNSModifyRequest(DNSModifyRequest.DELETE,
                                   dns.rdatatype.PTR, address, name)
        logging.debug("Reverse delete request for %s with existing value %s",
                      address, name)
        reverse_name, zone = self.__get_rev_name_and_zone(address)
        update = dns.update.Update(zone, keyring=self.keyring)
        update.delete(reverse_name, dns.rdatatype.PTR)
        result = dns.query.tcp(update, self.nameserver)
        logging.debug("Deleting reverse record result: %s", result)
        return DNSModifyAnswer(request, result.rcode())

    def delete_alias(self, alias, real_name=None):
        """
        Delete a CNAME record. If 'real_name' is not provided, the record will be searched for.
        """
        if not real_name:
            existing = self.forward_search.query(alias, SearchDNS.ALIAS)
            if existing.type == DNSSearchAnswer.NOT_FOUND:
                request = DNSModifyRequest(DNSModifyRequest.DELETE,
                                           dns.rdatatype.CNAME, alias, None)
                return DNSModifyAnswer(request, DNSModifyAnswer.CANCEL_REQUEST)
            real_name = existing.real_name
        request = DNSModifyRequest(DNSModifyRequest.DELETE,
                                   dns.rdatatype.CNAME, alias, real_name)
        logging.debug("Alias delete request for %s with existing value %s",
                      alias, real_name)
        shortname, zone = self._get_name_and_zone(alias)
        update = dns.update.Update(zone, keyring=self.keyring)
        update.delete(shortname, dns.rdatatype.CNAME)
        result = dns.query.tcp(update, self.nameserver)
        logging.debug("Deleting alias record result: %s", result)
        return DNSModifyAnswer(request, result.rcode())


def parse_key_file(kfile):
    """
    Given a TSIG key file (as regenerated by rndc), extract the key name and hash.
    """
    with open(kfile) as keyf:
        contents = keyf.readlines()
    for kline in contents:
        key_name_result = re.search(r'key (\S+) ', kline)
        if key_name_result:
            key_name = key_name_result.group(1)
        key_hash_result = re.search(r'secret \"(\S+)\"', kline)
        if key_hash_result:
            key_hash = key_hash_result.group(1).rstrip()
    return (key_name, key_hash)


def main():  # pylint: disable=too-many-branches
    """
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
        -h --help          Show this screen
        --debug <dfile>    Send debug logs to file
        --server <server>  Specify nameserver, if different from system default
        --key <kfile>      The TSIG key file containing name and hash
        --zone <zone>      Forward or reverse zone, if overriding name/address zone
    """
    arguments = docopt(str(main.__doc__))
    if arguments['--debug']:
        log_date = '%Y-%m-%d %H:%M:%S'
        log_form = '%(asctime)s %(message)s'
        logging.basicConfig(
            filename=arguments['--debug'],
            level=logging.DEBUG,
            format=log_form,
            datefmt=log_date)
    logging.debug("Arguments: %s", arguments)
    zone = arguments['--zone'] if '--zone' in arguments else None
    server = arguments['--server'] if '--server' in arguments else None
    name = arguments['<name>']
    address = arguments['<address>']
    alias = arguments['<alias>']
    if arguments['--key']:
        (key_name, key_hash) = parse_key_file(arguments['--key'])
    else:
        key_name = key_hash = None
    if arguments['add_reverse'] or arguments['delete_reverse']:
        modifier = ModifyDNS(server, None, zone, None, key_name, key_hash)
    else:
        modifier = ModifyDNS(server, zone, None, None, key_name, key_hash)
    result = []
    try:
        if arguments['add_forward']:
            logging.debug("Request to add forward entry for %s %s", name,
                          address)
            result.extend(modifier.add_forward(name, address))
        if arguments['add_reverse']:
            address = address.pop(0)
            logging.debug("Request to add reverse entry for %s %s", address,
                          name)
            result.append(modifier.add_reverse(address, name))
        if arguments['add_alias']:
            logging.debug("Request to add alias for %s %s", alias, name)
            result.append(modifier.add_alias(alias, name))
        if arguments['delete_forward']:
            logging.debug("Request to delete forward entry %s", name)
            result.append(modifier.delete_forward(name))
        if arguments['delete_reverse']:
            address = address.pop(0)
            logging.debug("Request to delete reverse entry %s", address)
            result.append(modifier.delete_reverse(address))
        if arguments['delete_alias']:
            logging.debug("Request to delete alias entry %s", alias)
            result.append(modifier.delete_alias(alias))
    except DNSModifyError as dme:
        print("Error encountered: {}".format(str(dme)))
    for res in result:
        print(res)


if __name__ == "__main__":
    from docopt import docopt
    main()
