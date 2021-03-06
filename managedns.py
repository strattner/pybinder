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
#import itertools
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

    def _add_history(self, result):
        """
        Add history of actions. Remove status (": completed successfully") as it's
        redundant at this point - only successful actions will be entered into history.
        """
        short_result = [x.request for x in result]
        if self.user:
            self.__class__.history[self.user].append(short_result)
        return result

    def get_history(self):
        """
        Return all modification events for the user associated with this instance.
        """
        if self.user:
            return self.__class__.history[self.user]
        return None

    def clear_history(self):
        """
        Clears user history.
        """
        if self.user:
            self.__class__.history[self.user] = []
        return None

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
        logging.debug("Iterator: Starting values: number %s and index %s", number, index)
        starting_index = int(index)
        index_padding = len(str(index))
        logging.debug("Iterator: Index padding %s", index_padding)
        try:
            starting_address = ipaddress.ip_address(ip_address)
        except ValueError:
            raise ManageDNSError(ManageDNSError.INVALID_ADDRESS + ip_address)
        for inc in range(int(number)):
            current_name = name + str(starting_index + inc).zfill(index_padding)
            current_address = starting_address + inc
            logging.debug("Iterator: generating record  %s %s", current_name, current_address)
            yield (current_name, str(current_address))

    @staticmethod
    def __raise_if_force(entry, force):
        """
        Simple function to raise an EXISTS error if force isn't True
        """
        if not force:
            raise ManageDNSError(ManageDNSError.EXISTS + entry)
        return None

    def __delete_or_raise(self, name=None, addr=None, force=False):
        """
        Given a name and optionally an IP, determine if these values already exist
        in DNS. If they do, and force is not True, raise an EXISTS error. If force
        is True, delete these records.
        """
        logging.debug("Request to delete or raise if found, name %s or address %s, force: %s",
                      name, addr, force)
        results = []
        existing_records = []
        if name:
            logging.debug("Performing forward search for %s", name)
            search_record = self.forward_search.query(name)
            if not search_record.type == DNSSearchAnswer.NOT_FOUND:
                self.__raise_if_force(name, force)
                logging.debug("Adding %s to existing record list", str(search_record))
                existing_records.append(search_record)
        if addr:
            logging.debug("Performing reverse search for %s", addr)
            address_record = self.reverse_search.query(addr)
            if not address_record.type == DNSSearchAnswer.NOT_FOUND:
                self.__raise_if_force(addr, force)
                logging.debug("Adding %s to existing record list", str(address_record))
                existing_records.append(address_record)
        for entry in existing_records:
            logging.debug("Existing record to be deleted %s", str(entry))
            if entry.type == DNSSearchAnswer.FORWARD:
                curr_addr = entry.addr
                results.append(self.delete_forward(name, curr_addr))
                results.append(self.delete_reverse(curr_addr, name))
            elif entry.type == DNSSearchAnswer.REVERSE:
                results.append(self.delete_reverse(addr, entry.name))
                results.append(self.delete_forward(entry.name, addr))
            elif entry.type == DNSSearchAnswer.ROUND_ROBIN:
                for address in entry.addr:
                    results.append(self.delete_forward(name, address))
                    results.append(self.delete_reverse(address, name))
            elif entry.type == DNSSearchAnswer.ALIAS:
                results.append(self.delete_alias(name, entry.real_name))
        return results

    def __delete_or_raise_range(self, name, ip_address, number, index, force=False, zone=None):  # pylint: disable=too-many-arguments
        """
        """
        results = []
        for current_name, current_ip in self.__range_iterator(name, ip_address, number, index):
            if zone:
                full_name = current_name + '.' + zone
            else:
                full_name = current_name
            logging.debug("Checking %s %s for deletion", full_name, current_ip)
            results.extend(self.__delete_or_raise(full_name, current_ip, force))
        return results

    def add_record(self, name, address, force=False):
        """
        Adds the A and PTR records - deleting any existing entries, if force is True.
        """
        shortname, zone = self._get_name_and_zone(name)
        result = []
        if isinstance(address, str):
            address = [address]
        # Need to separately loop to check for existence,
        # or round-robin entries will fail after first record is added
        for addr in address:
            result.extend(self.__delete_or_raise(shortname + '.' + zone, addr, force))
        for addr in address:
            result.extend(self.add_forward(name, addr))
            result.append(self.add_reverse(addr, shortname + '.' + zone))
        return self._add_history(result)

    def add_alias(self, alias, name, force=False):  # pylint: disable=arguments-differ
        """
        Add an alias - performs checking (force) before adding, unlike parent function.
        """
        result = []
        result.extend(self.__delete_or_raise(alias, None, force))
        result.append(super().add_alias(alias, name))
        return self._add_history(result)

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
            logging.debug("Got shortname %s and index %s from name %s", shortname, index, name)
        else:
            shortname, zone = self._get_name_and_zone(name)
        result = []
        result.extend(self.__delete_or_raise_range(shortname,
                                                   start_address, number, index, force, zone))
        for current_name, current_address in self.__range_iterator(shortname, start_address,
                                                                   number, index):
            full_name = current_name + '.' + zone
            result.extend(self.add_forward(full_name, current_address))
            result.append(self.add_reverse(current_address, full_name))
        return self._add_history(result)

    def delete_record(self, name_or_address):
        """
        Rely on __delete_or_raise to get rid of A + PTR, or CNAME records.
        """
        result = []
        try:
            address = ipaddress.ip_address(name_or_address)
            result.extend(self.__delete_or_raise(None, str(address), True))
        except ValueError:
            result.extend(self.__delete_or_raise(name_or_address, None, True))
        return self._add_history(result)

    def delete_range(self, name_or_address, number, index=None):
        """
        Determine whether name or IP was provided and call appropriate delete_range_by function.
        """
        result = []
        try:
            address = ipaddress.ip_address(name_or_address)
            result.extend(self.delete_range_by_address(address, number))
        except ValueError:
            result.extend(self.delete_range_by_name(name_or_address, number, index))
        return self._add_history(result)

    def delete_range_by_name(self, name, number, index=None):
        """
        Deletes records (A + PTR) based on a range of indexable names.
        """
        if not index:
            shortname, zone, index = self.__get_name_zone_and_index(name)
        else:
            shortname, zone = self._get_name_and_zone(name)
        result = []
        bogus_address = '10.1.1.1'  # We won't use the address, but iterator wants it
        for current_name, _ in self.__range_iterator(shortname, bogus_address, number, index):
            full_name = current_name + '.' + zone
            logging.debug("Request to delete or raise %s", full_name)
            result.extend(self.__delete_or_raise(full_name, None, True))
        return self._add_history(result)

    def delete_range_by_address(self, address, number):
        """
        Deletes records (PTR + A) based on a range of IPs.
        """
        bogus_name = 'notused'
        bogus_index = '001'
        result = []
        for _, current_address in self.__range_iterator(bogus_name, address, number, bogus_index):
            logging.debug("Request to delete or raise %s", current_address)
            result.extend(self.__delete_or_raise(None, current_address, True))
        return self._add_history(result)


def main():  # pylint: disable=too-many-locals
    """
    ManageDNS

    Usage:
    managedns.py add [--debug <dfile>] [--server <server>] [--key <kfile>] [--fzone <fzone>]
                     [--rzone <rzone>] [--force] <name> <address>...
    managedns.py delete [--debug <dfile>] [--server <server>] [--key <kfile>]
                        [--fzone <fzone>] [--rzone <rzone>] <name_or_address>
    managedns.py add_alias [--debug <dfile>] [--server <server>] [--key <kfile>]
                           [--fzone <fzone>] [--force] <alias> <name>
    managedns.py add_range [--debug <dfile>] [--server <server>] [--key <kfile>] [--fzone <fzone>]
                           [--rzone <rzone>] [--force] <name> <address> <num> [<index>]
    managedns.py delete_range [--debug <dfile>] [--server <server>] [--key <kfile>]
                           [--fzone <fzone>] [--rzone <rzone>] <name_or_address> <num> [<index>]
    managedns.py -h|--help

    Arguments:
        name             FQDN or shortname (first entry if adding a range)
        address          IP address (first entry if adding a range)
        alias            Alias entry (CNAME)
        num              Number of entries to create
        name_or_address  Either FQDN, shortname, or IP address

    Options:
        -h --help        Show this screen
        --debug <dfile>  Send debug logs to file
        --server <server>  Specify nameserver, if different from system default
        --key <kfile>      The TSIG key file containing name and hash
        --fzone <fzone>    The forward zone, if not obtainable from entry name
        --rzone <rzone>    The reverse zone, if not matching default from IP
        --force            Delete existing entries before adding new ones
        index              If not included in the start name, specify the index -
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
    name = arguments['<name>']
    address = arguments['<address>']
    name_or_address = arguments['<name_or_address>']
    alias = arguments['<alias>']
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
    try:
        if arguments['add_range']:
            address = address.pop(0)
            results = my_manager.add_range(name, address, number, start_index, force)
        elif arguments['add_alias']:
            results = my_manager.add_alias(alias, name, force)
        elif arguments['add']:
            results = my_manager.add_record(name, address, force)
        elif arguments['delete_range']:
            results = my_manager.delete_range(name_or_address, number, start_index)
        elif arguments['delete']:
            results = my_manager.delete_record(name_or_address)
        for res in results:
            print(res)
    except ManageDNSError as mde:
        print(mde)

if __name__ == "__main__":
    from docopt import docopt
    main()
