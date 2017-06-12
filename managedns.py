#!/usr/bin/python3
"""
managedns.py

Leverages searchdns and modifydns to make DNS management tasks easier.

Provides ability to add a range of values, as well as automatically add/remove
the associated forward and reverse entries. Will check for existing records
before overwriting, or will delete existing and create new in one sequence,
if requested.

Author: Scott Strattner (sstrattn@us.ibm.com)
"""

import re
import logging
import ipaddress
from modifydns import ModifyDNS, parse_key_file
from searchdns import DNSSearchAnswer

class ManageDNSError(Exception):
    """
    Collection of possible error situations when calling ManageDNS functions
    """

    NO_INDEX = "Index missing - required when specifying a range"
    INVALID_ADDRESS = "Not a valid IP address: "
    EXISTS = "Cannot make changes, existing record: "


class ManageDNS(ModifyDNS):
    """
    Extends ModifyDNS with user-based history, and additional methods to perform
    common DNS tasks.
    """

    history = {}

    def __init__(self, **kwargs):
        modify_params = ['nameserver', 'forward_zone', 'reverse_zone',
                         'ttl', 'key_name', 'key_hash']
        modify_kwargs = {modkey: kwargs[modkey] for modkey in modify_params if modkey in kwargs}
        super().__init__(**modify_kwargs)
        self.user = kwargs['user'] if 'user' in kwargs else None
        if self.user:
            logging.debug("Setting up history for user %s", self.user)
            self.__class__.history[self.user] = []

    def __get_name_zone_and_index(self, name):
        """
        Returns a three value tuple of the shortname, zone (if found), and the
        index. If the index cannot be determined from the name, it raises a
        ManageDNSError error.
        """
        shortname, zone = self._get_name_and_zone(name)
        index_search = re.search(r'(\d+)$', shortname)
        if not index_search:
            raise ManageDNSError(ManageDNSError.NO_INDEX)
        shortname = shortname[:-len(index_search.group(1))]
        logging.debug("Extracted short name %s in zone %s with starting index %s",
                      shortname, zone, index_search.group(1))
        return (shortname, zone, index_search.group(1))

    @staticmethod
    def __range_iterator(name, ip_address, number, index):
        """
        Given a name (without zone), starting ip, the number of entries, and
        the requested index identifier, yield each name,ip as a tuple.
        """
        starting_index = int(index)
        index_padding = len(str(index))
        try:
            starting_address = ipaddress.ip_address(ip_address)
        except ValueError:
            raise ManageDNSError(ManageDNSError.INVALID_ADDRESS + ip_address)
        for inc in range(int(number)):
            current_name = name + str(starting_index + inc).zfill(index_padding)
            current_address = starting_address + inc
            yield (current_name, str(current_address))

    @staticmethod
    def __raise_if_force(entry, force):
        """
        Simple function to raise an EXISTS error if force isn't True
        """
        if not force:
            raise ManageDNSError(ManageDNSError.EXISTS + entry)
        return None

    def __delete_or_raise(self, name, addr=None, force=False):
        """
        Given a name and optionally an IP, determine if these values already exist
        in DNS. If they do, and force is not True, raise an EXISTS error. If force
        is True, delete these records.
        """
        results = []
        existing_records = []
        search_record = self.forward_search.query(name)
        if not search_record.type == DNSSearchAnswer.NOT_FOUND:
            self.__raise_if_force(name, force)
            existing_records.append(search_record)
        if addr:
            address_record = self.reverse_search.query(addr)
            if not address_record.type == DNSSearchAnswer.NOT_FOUND:
                self.__raise_if_force(addr, force)
                existing_records.append(address_record)
        for entry in existing_records:
            if entry.type == DNSSearchAnswer.FORWARD:
                results.extend(self.delete_forward(name))
                results.extend(self.delete_reverse(entry.addr.pop(0)))
            elif entry.type == DNSSearchAnswer.REVERSE:
                results.extend(self.delete_reverse(addr))
                results.extend(self.delete_forward(entry.name))
            elif entry.type == DNSSearchAnswer.ROUND_ROBIN:
                results.extend(self.delete_forward(name))
                for address in entry.addr:
                    results.extend(self.delete_reverse(address))
            elif entry.type == DNSSearchAnswer.ALIAS:
                results.extend(self.delete_alias(name))
        return results

    def __delete_or_raise_range(self, name, ip_address, number, index, force=False):  # pylint: disable=too-many-arguments
        """
        """
        results = []
        for current_name, current_ip in self.__range_iterator(name, ip_address, number, index):
            results.extend(self.__delete_or_raise(current_name, current_ip, force))
        return results

    def add_record(self, name, address, force=False):
        """
        Adds the A and PTR records - deleting any existing entries, if force is True.
        """
        shortname, zone = self._get_name_and_zone(name)
        result = []
        result.extend(self.__delete_or_raise(shortname + '.' + zone, address, force))
        result.append(self.add_forward(name, address))
        result.append(self.add_reverse(address, name + '.' + zone))
        return result

    def add_range(self, name, start_address, number, index=None, force=False):  # pylint: disable=too-many-arguments
        """
        Index, if given, should be a string, so that the number of required digits (ie, zero
        padding) can be preserved. If not given, the index will be extracted from the given name
        (or raise an error).
        Force will add records without regard for existing entries. Otherwise, all entries will
        be checked, and if any exist (name or IP), will raise an error.
        """
        if not index:
            shortname, zone, index = self.__get_name_zone_and_index(name)
        else:
            shortname, zone = self._get_name_and_zone(name)
        result = []
        result.extend(self.__delete_or_raise_range(shortname + '.' + zone,
                                                   start_address, index, force))
        for current_name, current_address in self.__range_iterator(shortname, start_address,
                                                                   number, index):
            result.append(self.add_forward(current_name, current_address))
            result.append(self.add_reverse(current_address, current_name + '.' + zone))
        return result


def main():  # pylint: disable=too-many-locals
    """
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
    fzone = arguments['--fzone'] if '--fzone' in arguments else None
    rzone = arguments['--rzone'] if '--rzone' in arguments else None
    server = arguments['--server'] if '--server' in arguments else None
    force = arguments['--force']
    start_name = arguments['<start_name>']
    start_address = arguments['<start_address>']
    number = arguments['<num>']
    start_index = arguments['<index>'] if '<index>' in arguments else None
    if arguments['--key']:
        (key_name, key_hash) = parse_key_file(arguments['--key'])
    else:
        key_name = key_hash = None
    my_arguments = {'nameserver': server,
                    'forward_zone': fzone,
                    'reverse_zone': rzone,
                    'key_name': key_name,
                    'key_hash': key_hash,
                    'ttl': 3000}
    my_manager = ManageDNS(**my_arguments)
    results = my_manager.add_range(start_name, start_address, number, start_index, force)
    print(results)

if __name__ == "__main__":
    from docopt import docopt
    main()
