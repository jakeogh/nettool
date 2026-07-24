#!/usr/bin/env python3

import random
import socket
import struct
from pathlib import Path
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import hs
import netifaces
import requests
from asserttool import ic
from eprint import eprint
from retry_on_exception import retry_on_exception

signal(SIGPIPE, SIG_DFL)

_ip = hs.Command("ip")


class AliasExistsError(ValueError):
    pass


def get_network_interfaces() -> list[str]:
    skip_interfaces = {"lo", "dummy0", "teql0"}
    return [_ for _ in netifaces.interfaces() if _ not in skip_interfaces]


def generate_network_interface_help() -> str:
    # \b prevents click from rewrapping
    help_text = "Available network interfaces: "
    for port in get_network_interfaces():
        help_text += "\b\n" + str(port)
    return help_text


def set_interface_link_up(interface: str) -> None:
    _ip("link", "set", "up", interface)


def set_interface_link_down(interface: str) -> None:
    _ip("link", "set", "down", interface)


def interface_link_is_up(interface: str) -> bool:
    with open(f"/sys/class/net/{interface}/flags", "r", encoding="utf8") as fh:
        return bool(int(fh.read(), 16) & 0x1)


def interface_link_light_is_on(interface: str) -> bool:
    with open(f"/sys/class/net/{interface}/operstate", "r", encoding="utf8") as fh:
        return fh.read().strip() == "up"


def get_hostname() -> str:
    return socket.gethostname()


def alias_add(*, ip_with_subnet: str, device: str) -> None:
    assert "/" in ip_with_subnet
    if not interface_link_is_up(device):
        eprint(f"WARNING: interface {device} is not up")
    try:
        _ip("address", "add", ip_with_subnet, "dev", device)
    except hs.ErrorReturnCode_2 as e:
        message = e.args[0] if e.args else ""
        if "RTNETLINK answers: File exists" in message:
            raise AliasExistsError(message) from e
        if "Error: ipv4: Address already assigned." in message:
            raise AliasExistsError(message) from e
        raise


def alias_remove(*, ip_with_subnet: str, device: str) -> None:
    assert "/" in ip_with_subnet
    _ip("address", "del", ip_with_subnet, "dev", device)


# https://public-dns.info/nameservers.txt
def get_public_dns_server() -> str:
    servers = [
        "8.8.8.8",  # goog
        "8.8.4.4",
        "1.1.1.1",  # cloudf
    ]
    return random.choice(servers)


# https://stackoverflow.com/questions/3764291/how-can-i-see-if-theres-an-available-and-active-network-connection-in-python
def internet_available() -> bool:
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
def get_default_gateway_linux() -> None | str:
    with open("/proc/net/route", encoding="utf8") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    return None


def tcp_port_in_use(port: int) -> bool:
    assert isinstance(port, int)
    for line in hs.Command("netstat")("-a", "-n", "-l"):
        if line.startswith("tcp"):
            if f":{port}" in line:
                ic(line)
                return True

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        _result = s.connect_ex(("localhost", port)) == 0
        ic(port, _result)
        return _result


def get_ip_addresses_for_interface(interface: str) -> list[str]:
    addresses = netifaces.ifaddresses(interface)
    try:
        addresses = addresses[netifaces.AF_INET]
    except KeyError:
        return []
    addresses = [ip["addr"] for ip in addresses]
    ic(addresses)
    return addresses


def get_mac_for_interface(interface: str) -> bytes:
    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
    ic(mac)
    return bytes.fromhex("".join(mac.split(":")))


@retry_on_exception(exception=ConnectionError)
def download_file(
    *,
    url: str,
    destination_dir: None | Path = None,
    force: bool = False,
    proxy_dict: None | dict = None,
    progress: bool = False,
) -> Path | str:
    eprint("downloading:", url)
    local_filename: None | Path = None
    if destination_dir:
        destination_dir = Path(destination_dir)
        local_filename = destination_dir / url.split("/")[-1]
        if force:
            local_filename.unlink(missing_ok=True)

    eprint(f"{destination_dir=}")
    ic(proxy_dict)
    r = requests.get(
        url,
        stream=True,
        proxies=proxy_dict,
        timeout=60,
    )
    r.raise_for_status()

    if local_filename:
        byte_count = 0
        try:
            with open(local_filename, "bx") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
                        byte_count += len(chunk)
                    if progress:
                        eprint("bytes:", byte_count)
        except FileExistsError:
            eprint("skipping download, file exists:", local_filename.as_posix())
        r.close()
        return local_filename

    text = r.text
    r.close()
    return text


def check_interface_speed(interface: str = "eth0") -> int:
    with open(f"/sys/class/net/{interface}/speed", "r", encoding="utf8") as fh:
        speed_mbps = int(fh.read().strip())

    # -1: interface down or speed unknown
    if speed_mbps == -1:
        eprint(f"WARNING: interface {interface} is down or speed is unknown")
    elif speed_mbps < 1000:
        eprint(f"WARNING: interface {interface} speed is {speed_mbps} Mbps (less than gigabit)")
    return speed_mbps
