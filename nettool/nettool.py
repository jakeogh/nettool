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
from math import inf
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal
from typing import ByteString
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Union

import click
import netifaces
import requests
import sh
from asserttool import ic
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tv
from eprint import eprint
from pathtool import read_file_bytes
from retry_on_exception import retry_on_exception
from unmp import unmp

signal(SIGPIPE,SIG_DFL)


def get_timestamp():
    timestamp = str("%.22f" % time.time())
    return timestamp


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
                                   verbose: Union[bool, int, float],
                                   ):
    addresses = netifaces.ifaddresses(interface)
    if verbose == inf:
        ic(addresses)
    try:
        addresses = addresses[netifaces.AF_INET]
    except KeyError:
        return []
    addresses = [ip['addr'] for ip in addresses]
    if verbose == inf:
        ic(addresses)
    return addresses


def get_mac_for_interface(interface: str,
                          verbose: Union[bool, int, float],
                          ):
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    if verbose:
        ic(mac)
    mac = ''.join(mac.split(':'))
    mac = bytes.fromhex(mac)
    if verbose:
        ic(mac)
    return mac


def construct_proxy_dict(verbose: Union[bool, int, float],
                         ):
    proxy_config = read_file_bytes('/etc/portage/proxy.conf').decode('utf8').split('\n')
    if verbose:
        ic(proxy_config)
    proxy_dict = {}
    for line in proxy_config:
        if verbose == inf:
            ic(line)
        scheme = line.split('=')[0].split('_')[0]
        line = line.split('=')[-1]
        line = line.strip('"')
        #scheme = line.split('://')[0]
        if verbose == inf:
            ic(scheme)
        proxy_dict[scheme] = line
        #proxy = line.split('://')[-1].split('"')[0]
    ic(proxy_dict)
    return proxy_dict


# todo, add asc_sig options
@retry_on_exception(exception=ConnectionError)
def download_file(*,
                  url: str,
                  destination_dir: Optional[Path] = None,
                  force: bool = False,
                  proxy_dict: Optional[dict] = None,
                  progress: bool = False,
                  verbose: Union[bool, int, float],
                  ):

    eprint("downloading:", url)
    if destination_dir:
        destination_dir = Path(destination_dir)
        local_filename = destination_dir /  Path(url.split('/')[-1])
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
    byte_count = 0
    if local_filename:
        try:
            with open(local_filename, 'bx') as fh:
                for chunk in r.iter_content(chunk_size=1024*1024):
                    if chunk:
                        fh.write(chunk)
                    if progress:
                        eprint('bytes:', byte_count)
        except FileExistsError:
            eprint("skipping download, file exists:", local_filename.as_posix())
        r.close()
        return local_filename

    text = r.text
    r.close()
    return text



@click.command()
@click.argument("interfaces", type=str, nargs=-1)
@click_add_options(click_global_options)
@click.pass_context
def cli(ctx,
        interfaces: Optional[Tuple[str, ...]],
        verbose: Union[bool, int, float],
        verbose_inf: bool,
        ):

    ctx.ensure_object(dict)
    tty, verbose = tv(ctx=ctx,
                      verbose=verbose,
                      verbose_inf=verbose_inf,
                      )

    if interfaces:
        iterator = interfaces
    else:
        iterator = unmp(valid_types=[str,], verbose=verbose,)

    index = 0
    for index, interface in enumerate(iterator):
        if verbose:
            ic(index, interface)

        print(get_ip_addresses_for_interface(interface=interface,
                                             verbose=verbose,
                                             ))
        print(get_mac_for_interface(interface=interface,
                                    verbose=verbose,
                                    ))
