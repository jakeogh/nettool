#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=useless-suppression             # [I0021]
# pylint: disable=missing-docstring               # [C0111] docstrings are always outdated and wrong
# pylint: disable=fixme                           # [W0511] todo is encouraged
# pylint: disable=line-too-long                   # [C0301]
# pylint: disable=too-many-instance-attributes    # [R0902]
# pylint: disable=too-many-lines                  # [C0302] too many lines in module
# pylint: disable=invalid-name                    # [C0103] single letter var names, name too descriptive
# pylint: disable=too-many-return-statements      # [R0911]
# pylint: disable=too-many-branches               # [R0912]
# pylint: disable=too-many-statements             # [R0915]
# pylint: disable=too-many-arguments              # [R0913]
# pylint: disable=too-many-nested-blocks          # [R1702]
# pylint: disable=too-many-locals                 # [R0914]
# pylint: disable=too-few-public-methods          # [R0903]
# pylint: disable=no-member                       # [E1101] no member for base
# pylint: disable=attribute-defined-outside-init  # [W0201]
# pylint: disable=too-many-boolean-expressions    # [R0916] in if statement

from __future__ import annotations

import random
import socket
import struct
import time
from collections.abc import Sequence
from math import inf
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click
import netifaces
import requests
from asserttool import ic
from click_auto_help import AHGroup
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tv
from eprint import eprint
from mptool import mpd_enumerate
from mptool import output
from pathtool import read_file_bytes
from retry_on_exception import retry_on_exception
from unmp import unmp

signal(SIGPIPE, SIG_DFL)


# https://public-dns.info/nameservers.txt
def get_public_dns_server():
    servers = [
        "8.8.8.8",  # goog
        "8.8.4.4",
        "1.1.1.1",  # cloudf
    ]
    return random.choice(servers)


# https://stackoverflow.com/questions/3764291/how-can-i-see-if-theres-an-available-and-active-network-connection-in-python
def internet_available():
    host = get_public_dns_server()
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 53))
        return True
    except socket.error:
        return False


def get_default_gateway(verbose: bool | int | float):
    gateways = netifaces.gateways()
    if verbose:
        ic(gateways)

    return gateways


# https://gist.github.com/ssokolow/1059982
def get_default_gateway_linux(verbose: bool | int | float):
    with open("/proc/net/route", encoding="utf8") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))


def get_timestamp():
    timestamp = str("%.22f" % time.time())
    return timestamp


if not Path("/bin/ip").exists():
    try:
        from scapy.all import get_windows_if_list
    except ImportError:

        def get_windows_if_list():
            assert False

else:

    def get_windows_if_list():
        assert False


def tcp_port_in_use(port: int):
    if not isinstance(port, int):
        raise ValueError("port must be type int, not:", type(port), port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def get_network_interfaces():
    ports = netifaces.interfaces()
    skip_interfaces = ["lo", "dummy0", "teql0"]
    for interface in skip_interfaces:
        try:
            ports.remove(interface)
        except ValueError:
            pass
    return ports


def get_name_for_windows_network_uuid(uuid):
    if not uuid.startswith("{"):
        return uuid  # return non win device, should tuple

    assert uuid.endswith("}")
    for item in get_windows_if_list():
        if item["guid"] == uuid:
            return (item["name"], item["description"])
    raise ValueError(uuid)


def get_ip_addresses_for_interface(
    *,
    interface: str,
    verbose: bool | int | float,
):
    addresses = netifaces.ifaddresses(interface)
    if verbose == inf:
        ic(addresses)
    try:
        addresses = addresses[netifaces.AF_INET]
    except KeyError:
        return []
    addresses = [ip["addr"] for ip in addresses]
    if verbose == inf:
        ic(addresses)
    return addresses


def get_mac_for_interface(
    interface: str,
    verbose: bool | int | float,
):
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
    if verbose:
        ic(mac)
    mac = "".join(mac.split(":"))
    mac = bytes.fromhex(mac)
    if verbose:
        ic(mac)
    return mac


def construct_proxy_dict(
    verbose: bool | int | float,
):
    proxy_config = (
        read_file_bytes("/etc/portage/proxy.conf", verbose=verbose)
        .decode("utf8")
        .split("\n")
    )
    if verbose:
        ic(proxy_config)
    proxy_dict = {}
    for line in proxy_config:
        if verbose == inf:
            ic(line)
        scheme = line.split("=")[0].split("_")[0]
        line = line.split("=")[-1]
        line = line.strip('"')
        # scheme = line.split('://')[0]
        if verbose == inf:
            ic(scheme)
        proxy_dict[scheme] = line
        # proxy = line.split('://')[-1].split('"')[0]
    ic(proxy_dict)
    return proxy_dict


# todo, add asc_sig options
@retry_on_exception(exception=ConnectionError)
def download_file(
    *,
    url: str,
    destination_dir: None | Path = None,
    force: bool = False,
    proxy_dict: None | dict = None,
    progress: bool = False,
    verbose: bool | int | float,
):

    eprint("downloading:", url)
    if destination_dir:
        destination_dir = Path(destination_dir)
        local_filename = destination_dir / Path(url.split("/")[-1])
    else:
        local_filename = None

    eprint(f"{destination_dir=}")
    # if force:
    #    os.unlink(local_filename)

    # proxy_dict = {}
    # if proxy:
    #    verify(not proxy.startswith('http'))
    #    verify(len(proxy.split(":")) == 2)
    #    proxy_dict["http"] = proxy
    #    proxy_dict["https"] = proxy

    ic(proxy_dict)
    r = requests.get(url, stream=True, proxies=proxy_dict, timeout=60)
    byte_count = 0
    if local_filename:
        try:
            with open(local_filename, "bx") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
                    if progress:
                        eprint("bytes:", byte_count)
        except FileExistsError:
            eprint("skipping download, file exists:", local_filename.as_posix())
        r.close()
        return local_filename

    text = r.text
    r.close()
    return text


@click.group(no_args_is_help=True, cls=AHGroup)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
) -> None:

    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )


@cli.command("default-gw")
@click.argument("keys", type=str, nargs=-1)
@click_add_options(click_global_options)
@click.pass_context
def _default_gw(
    ctx,
    keys: Sequence[str],
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
):

    ctx.ensure_object(dict)
    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    iterator: Sequence[dict | str] = unmp(
        valid_types=[
            dict,
            str,
        ],
        verbose=verbose,
    )

    index = 0
    for index, _mpobject, multi_key in mpd_enumerate(iterator, verbose=verbose):
        # this check could be moved to output() but then we cant exit on error now
        if multi_key:
            assert len(keys) > 0

        default_gw = get_default_gateway(verbose=verbose)
        output(
            default_gw,
            reason=_mpobject,
            tty=tty,
            dict_output=dict_output,
            verbose=verbose,
        )


@cli.command("info")
@click_add_options(click_global_options)
@click.pass_context
def _info(
    ctx,
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
):

    ctx.ensure_object(dict)
    tty, verbose = tv(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
    )

    iterator: Sequence[dict | str] = unmp(
        valid_types=[
            dict,
            str,
        ],
        verbose=verbose,
    )

    index = 0
    for index, _mpobject in enumerate(iterator):
        if verbose:
            ic(index, _mpobject)
        interface = None
        if isinstance(_mpobject, dict):
            for _k, _v in _mpobject.items():
                interface = _v
                break
        else:
            interface = _mpobject
            _k = interface

        output(
            get_ip_addresses_for_interface(
                interface=interface,
                verbose=verbose,
            ),
            reason=_k,
            tty=tty,
            dict_output=dict_output,
            verbose=verbose,
        )
        output(
            get_mac_for_interface(
                interface=interface,
                verbose=verbose,
            ),
            reason=_k,
            tty=tty,
            dict_output=dict_output,
            verbose=verbose,
        )
