#!/usr/bin/python3
"""
 searchdns

 Query one or more records in DNS, using either system default or
 specified nameserver and/or search domain.

 Author: Scott Strattner (sstrattn@us.ibm.com)

 Copyright (c) 2017 IBM Corp.
 All Rights Reserved

"""
import re
import logging
import ipaddress
import dns.resolver
import dns.name
import dns.reversename


class DNSSearchAnswerError(Exception):  # pylint: disable=missing-docstring
    pass


class DNSSearchAnswer(object):  # pylint: disable=too-few-public-methods
    """
    Parses and stores the answer to a SearchDNS query.
    Only understands A, PTR, and CNAME records.
    """

    FORWARD = "A"
    REVERSE = "PTR"
    ALIAS = "CNAME"
    ROUND_ROBIN = "Round robin"
    NOT_FOUND = "not found in DNS"

    def __init__(self, entry, value=None):
        logging.debug("Inserting DNSSearchAnswer %s %s", entry, value)
        self.entry = entry
        if not value:
            self.type = DNSSearchAnswer.NOT_FOUND
        else:
            self.__parse_answer(value)

    def __parse_answer(self, answer):
        first_result = str(answer.pop(0))
        logging.debug("Parsing first result: %s", first_result)
        result_type_search = re.search(r'IN (\S+) (\S+)$', first_result)
        result_type = result_type_search.group(1)
        result_answer = result_type_search.group(2)
        logging.debug("Result type %s with value %s", result_type,
                      result_answer)
        if result_type == DNSSearchAnswer.ALIAS:
            self.type = DNSSearchAnswer.ALIAS
            self.real_name = result_answer
        elif result_type == DNSSearchAnswer.FORWARD:
            self.type = DNSSearchAnswer.FORWARD
            self.addr = result_answer
            if answer:
                self.addr = [self.addr]
                self.type = DNSSearchAnswer.ROUND_ROBIN
                for ans in answer:
                    next_ip_search = re.search(r'IN A (\S+)$', ans)
                    self.addr.append(next_ip_search.group(1))
        elif result_type == DNSSearchAnswer.REVERSE:
            self.type = DNSSearchAnswer.REVERSE
            self.name = result_answer
        else:
            raise DNSSearchAnswerError(
                "Unrecognized DNS response: {}".format(answer))
        return True

    def __str__(self):
        if self.type == DNSSearchAnswer.NOT_FOUND:
            return self.entry + " " + self.type
        return_string = self.entry + " "
        if self.type == DNSSearchAnswer.ALIAS:
            return_string += "(alias for) " + self.real_name
        if self.type == DNSSearchAnswer.ROUND_ROBIN:
            return_string += " ".join(self.addr)
        if self.type == DNSSearchAnswer.FORWARD:
            return_string += self.addr
        if self.type == DNSSearchAnswer.REVERSE:
            return_string += self.name
        return return_string


class SearchDNS(object):
    """
    Performs DNS query against system or specified nameserver,
    returns results as DNSSearchAnswer instance.
    """

    FORWARD = "A"
    REVERSE = "PTR"
    ALIAS = "CNAME"
    NORMAL = [FORWARD, REVERSE]

    def __init__(self, nameserver=None, zone=None):
        self.nameserver = nameserver
        self.zone = zone
        self.searcher = dns.resolver.Resolver()
        self.searcher.set_flags(0)  # do not perform recursive query
        if self.nameserver:
            logging.debug("Using %s as nameserver", self.nameserver)
            self.searcher.nameservers = [self.nameserver]
        if self.zone:
            logging.debug("Using %s as default domain", self.zone)
            self.searcher.search = [dns.name.from_text(self.zone)]

    @staticmethod
    def is_address(entry):  # pylint: disable=missing-docstring
        try:
            _ = ipaddress.ip_address(entry)
            return True
        except ValueError:
            return False

    def query(self, entry, search_type=None):  # pylint: disable=missing-docstring
        logging.debug("Performing a search for %s", entry)
        search_entry = entry
        if not search_type:
            if SearchDNS.is_address(entry):
                search_type = SearchDNS.REVERSE
                search_entry = dns.reversename.from_address(entry)
            else:
                search_type = SearchDNS.FORWARD
        try:
            answer = self.searcher.query(search_entry, search_type).response
            answer_list = str(answer.answer.pop(0)).splitlines()
            logging.debug("Answer: %s", answer_list)
            return DNSSearchAnswer(entry, answer_list)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return DNSSearchAnswer(entry)


def main():
    """
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
    """

    arguments = docopt(str(main.__doc__))
    if arguments['--debug']:
        print("Running in debug mode to {}".format(arguments['--debug']))
        log_date = '%Y-%m-%d %H:%M:%S'
        log_form = '%(asctime)s %(message)s'
        logging.basicConfig(
            filename=arguments['--debug'],
            level=logging.DEBUG,
            format=log_form,
            datefmt=log_date)
        logging.debug("Program arguments: %s", arguments)
    nameserver = arguments['--server'] if '--server' in arguments else None
    domain = arguments['--domain'] if '--domain' in arguments else None
    searcher = SearchDNS(nameserver, domain)
    for query in arguments['<query>']:
        print(searcher.query(query))


if __name__ == "__main__":
    from docopt import docopt
    main()
