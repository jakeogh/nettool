#!/usr/bin/env python3
# -*- coding: utf8 -*-


from __future__ import annotations

import random
import socket
import struct
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import netifaces
import requests
import sh
from asserttool import ic
from eprint import eprint
from retry_on_exception import retry_on_exception

signal(SIGPIPE, SIG_DFL)


class AliasExistsError(ValueError):
    pass


def generate_network_interface_help():
    help_text = "Available network interfaces: "
    ports = get_network_interfaces()
    for port in ports:
        help_text += "\b\n" + str(port)

    help_text.replace("\n\n", "\n")
    return help_text


def get_network_interfaces() -> list[str]:
    _interfaces = netifaces.interfaces()
    skip_interfaces = ["lo", "dummy0", "teql0"]
    for _ in skip_interfaces:
        try:
            _interfaces.remove(_)
        except ValueError:
            pass
    return _interfaces


def set_interface_link_up(interface: str) -> None:
    sh.ip(
        "link",
        "set",
        "up",
        interface,
    )


def set_interface_link_down(interface: str) -> None:
    sh.ip(
        "link",
        "set",
        "down",
        interface,
    )


def interface_link_is_up(interface: str) -> bool:
    with open(f"/sys/class/net/{interface}/flags", "r", encoding="utf8") as fh:
        _content = fh.read()
        _result = int(_content, 16) & 0x1
        return bool(_result)


def interface_link_light_is_on(interface: str) -> bool:
    with open(f"/sys/class/net/{interface}/operstate", "r", encoding="utf8") as fh:
        _content = fh.read()
        if _content.strip() == "up":
            return True
    return False


def get_hostname() -> str:
    return socket.gethostname()


def alias_add(*, ip_with_subnet: str, device: str):
    assert "/" in ip_with_subnet
    if not interface_link_is_up(device):
        eprint(f"WARNING: interface {device} is not up")
    ip_command = sh.Command("ip")
    result = None
    try:
        result = ip_command(
            "address",
            "add",
            ip_with_subnet,
            "dev",
            device,
        )
    except sh.ErrorReturnCode_2 as e:
        ic(e)
        ic(e.args)
        ic(e.args[0])
        ic(result)
        if hasattr(e, "args"):
            if "RTNETLINK answers: File exists" in e.args[0]:
                raise AliasExistsError(e.args[0])
            if "Error: ipv4: Address already assigned." in e.args[0]:
                raise AliasExistsError(e.args[0])
        raise e


def alias_remove(*, ip_with_subnet: str, device: str):
    assert "/" in ip_with_subnet
    sh.ip(
        "address",
        "del",
        ip_with_subnet,
        "dev",
        device,
    )


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


def get_default_gateway():
    gateways = netifaces.gateways()
    ic(gateways)

    return gateways


# https://gist.github.com/ssokolow/1059982
def get_default_gateway_linux():
    with open("/proc/net/route", encoding="utf8") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    # if not Path("/bin/ip").exists():
    #    try:
    #        from scapy.all import get_windows_if_list
    #    except ImportError:
    #
    #        def get_windows_if_list():
    #            assert False
    # else:
    #
    #    def get_windows_if_list():
    #        assert False


def tcp_port_in_use(
    port: int,
):
    # eprint(port)
    # ic(port)
    for line in sh.netstat("-a", "-n", "-l"):
        if line.startswith("tcp"):
            if f":{port}" in line:
                ic(line)
                return True

    if not isinstance(port, int):
        raise ValueError("port must be type int, not:", type(port), port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        _result = s.connect_ex(("localhost", port)) == 0
        ic(port, _result)
        return _result

    # def get_name_for_windows_network_uuid(uuid):
    #    if not uuid.startswith("{"):
    #        return uuid  # return non win device, should tuple
    #
    #    assert uuid.endswith("}")
    #    for item in get_windows_if_list():
    #        if item["guid"] == uuid:
    #            return (item["name"], item["description"])
    #    raise ValueError(uuid)


def get_ip_addresses_for_interface(
    interface: str,
) -> list[str]:
    addresses = netifaces.ifaddresses(interface)
    # ic(addresses)
    try:
        addresses = addresses[netifaces.AF_INET]
    except KeyError:
        return []
    addresses = [ip["addr"] for ip in addresses]
    ic(addresses)
    return addresses


def get_mac_for_interface(
    interface: str,
):
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
    ic(mac)
    mac = "".join(mac.split(":"))
    mac = bytes.fromhex(mac)
    # ic(mac)
    return mac


# todo, add asc_sig options
@retry_on_exception(exception=ConnectionError)
def download_file(
    *,
    url: str,
    destination_dir: None | Path = None,
    force: bool = False,
    proxy_dict: None | dict = None,
    progress: bool = False,
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
    r = requests.get(
        url,
        stream=True,
        proxies=proxy_dict,
        timeout=60,
    )
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


# def get_mac_for_interface(
#    interface: str,
# ):
#    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
#    ic(mac)
#    mac = "".join(mac.split(":"))
#    mac = bytes.fromhex(mac)
#    ic(mac)
#    return mac
