#!/usr/bin/env python3
# -*- coding: utf8 -*-

# flake8: noqa           # flake8 has no per file settings :(
# pylint: disable=C0111  # docstrings are always outdated and wrong
# pylint: disable=W0511  # todo is encouraged
# pylint: disable=C0301  # line too long
# pylint: disable=R0902  # too many instance attributes
# pylint: disable=C0302  # too many lines in module
# pylint: disable=C0103  # single letter var names, func name too descriptive
# pylint: disable=R0911  # too many return statements
# pylint: disable=R0912  # too many branches
# pylint: disable=R0915  # too many statements
# pylint: disable=R0913  # too many arguments
# pylint: disable=R1702  # too many nested blocks
# pylint: disable=R0914  # too many local variables
# pylint: disable=R0903  # too few public methods
# pylint: disable=E1101  # no member for base
# pylint: disable=W0201  # attribute defined outside __init__
# pylint: disable=R0916  # Too many boolean expressions in if statement
# pylint: disable=C0305  # Trailing newlines editor should fix automatically, pointless warning

import os
import sys
import time
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click

signal(SIGPIPE,SIG_DFL)
from pathlib import Path
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

import netifaces
import requests
from asserttool import nevd
from enumerate_input import enumerate_input
from pathtool import read_file_bytes
from retry_on_exception import retry_on_exception


def eprint(*args, **kwargs):
    if 'file' in kwargs.keys():
        kwargs.pop('file')
    print(*args, file=sys.stderr, **kwargs)


try:
    from icecream import ic  # https://github.com/gruns/icecream
    from icecream import icr  # https://github.com/jakeogh/icecream
except ImportError:
    ic = eprint
    icr = eprint


# import pdb; pdb.set_trace()
# #set_trace(term_size=(80, 24))
# from pudb import set_trace; set_trace(paused=False)

##def log_uncaught_exceptions(ex_cls, ex, tb):
##   eprint(''.join(traceback.format_tb(tb)))
##   eprint('{0}: {1}'.format(ex_cls, ex))
##
##sys.excepthook = log_uncaught_exceptions


def get_timestamp():
    timestamp = str("%.22f" % time.time())
    return timestamp


def validate_slice(slice_syntax):
    assert isinstance(slice_syntax, str)
    for c in slice_syntax:
        if c not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '[', ']', ':']:
            raise ValueError(slice_syntax)
    return slice_syntax


try:
    from scapy.all import get_windows_if_list
except ImportError:
    def get_windows_if_list():
        assert False


def get_network_interfaces():
    ports = netifaces.interfaces()
    skip_interfaces = ['lo', 'dummy0', 'teql0']
    for interface in skip_interfaces:
        try:
            ports.remove(interface)
        except ValueError:
            pass
    return ports


def get_name_for_windows_network_uuid(uuid):
    if not uuid.startswith('{'):
        return uuid     # return non win device, should tuple

    assert uuid.endswith('}')
    for item in get_windows_if_list():
        if item['guid'] == uuid:
            return (item['name'], item['description'])
    raise ValueError(uuid)


def get_ip_addresses_for_interface(*,
                                   interface: str,
                                   verbose: bool,
                                   debug: bool,
                                   ):
    addresses = netifaces.ifaddresses(interface)
    if debug:
        ic(addresses)
    try:
        addresses = addresses[netifaces.AF_INET]
    except KeyError:
        return []
    addresses = [ip['addr'] for ip in addresses]
    if debug:
        ic(addresses)
    return addresses


def get_mac_for_interface(interface: str,
                          verbose: bool,
                          debug: bool,
                          ):
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    if verbose:
        ic(mac)
    mac = ''.join(mac.split(':'))
    mac = bytes.fromhex(mac)
    if verbose:
        ic(mac)
    return mac


def construct_proxy_dict():
    proxy_config = read_file_bytes('/etc/portage/proxy.conf').decode('utf8').split('\n')
    ic(proxy_config)
    proxy_dict = {}
    for line in proxy_config:
        ic(line)
        scheme = line.split('=')[0].split('_')[0]
        line = line.split('=')[-1]
        line = line.strip('"')
        #scheme = line.split('://')[0]
        ic(scheme)
        proxy_dict[scheme] = line
        #proxy = line.split('://')[-1].split('"')[0]
    return proxy_dict


def download_file(*,
                  url: str,
                  destination_dir: Optional[Path] = None,
                  force: bool = False,
                  proxy_dict: Optional[dict] = None,
                  ):

    eprint("downloading:", url)
    if destination_dir:
        local_filename = destination_dir + '/' + url.split('/')[-1]
    else:
        local_filename = None

    #if force:
    #    os.unlink(local_filename)

    #proxy_dict = {}
    #if proxy:
    #    verify(not proxy.startswith('http'))
    #    verify(len(proxy.split(":")) == 2)
    #    proxy_dict["http"] = proxy
    #    proxy_dict["https"] = proxy

    ic(proxy_dict)
    r = requests.get(url, stream=True, proxies=proxy_dict)
    if local_filename:
        try:
            with open(local_filename, 'bx') as fh:
                for chunk in r.iter_content(chunk_size=1024*1024):
                    if chunk:
                        fh.write(chunk)
        except FileExistsError:
            eprint("skipping download, file exists:", local_filename)
        r.close()
        return local_filename

    text = r.text
    r.close()
    return text



@click.command()
@click.argument("interfaces", type=str, nargs=-1)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def cli(ctx,
        interfaces: Optional[Tuple[str, ...]],
        verbose: bool,
        debug: bool,
        ):

    ctx.ensure_object(dict)
    null, end, verbose, debug = nevd(ctx=ctx,
                                     printn=False,
                                     ipython=False,
                                     verbose=verbose,
                                     debug=debug,)

    iterator = interfaces

    index = 0
    for index, interface in enumerate_input(iterator=iterator,
                                            dont_decode=False,  # interfaces are ascii
                                            null=null,
                                            progress=False,
                                            skip=None,
                                            head=None,
                                            tail=None,
                                            debug=debug,
                                            verbose=verbose,
                                            ):

        if verbose:  # or simulate:
            ic(index, interface)

        print(get_ip_addresses_for_interface(interface=interface,
                                             verbose=verbose,
                                             debug=debug,))
        print(get_mac_for_interface(interface=interface,
                                    verbose=verbose,
                                    debug=debug,))
