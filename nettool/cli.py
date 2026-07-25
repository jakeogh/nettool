#!/usr/bin/env python3

import sys
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click
from asserttool import ic
from asserttool import icp
from click_auto_help import AHGroup
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tvicgvd
from eprint import eprint
from globalverbose import gvd
from mptool import output
from unmp import unmp

from nettool import AliasExistsError
from nettool import alias_add
from nettool import alias_remove
from nettool import get_default_gateway
from nettool import get_ip_addresses_for_interface
from nettool import get_mac_for_interface
from nettool import internet_available
from nettool import set_interface_link_down
from nettool import set_interface_link_up
from nettool import tcp_port_in_use

signal(SIGPIPE, SIG_DFL)


@click.group(no_args_is_help=True, cls=AHGroup)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx: click.Context,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )


@cli.command("default-gw")
@click.argument("keys", type=str, nargs=-1)
@click_add_options(click_global_options)
@click.pass_context
def _default_gw(
    ctx: click.Context,
    keys: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )

    for _mpobject in unmp(valid_types=(dict, str)):
        default_gw = get_default_gateway()
        output(
            default_gw,
            reason=_mpobject,
            tty=tty,
            dict_output=dict_output,
        )


@cli.command("info")
@click_add_options(click_global_options)
@click.pass_context
def _info(
    ctx: click.Context,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )

    for index, _mpobject in enumerate(unmp(valid_types=(dict, str))):
        ic(index, _mpobject)
        if isinstance(_mpobject, dict):
            _k, interface = next(iter(_mpobject.items()))
        else:
            interface = _mpobject
            _k = interface

        output(
            get_ip_addresses_for_interface(
                interface=interface,
            ),
            reason=_k,
            tty=tty,
            dict_output=dict_output,
        )
        output(
            get_mac_for_interface(
                interface=interface,
            ),
            reason=_k,
            tty=tty,
            dict_output=dict_output,
        )


@cli.command("tcp-port-in-use")
@click.argument("port", type=int, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _tcp_port_in_use(
    ctx: click.Context,
    port: int,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )

    _result = tcp_port_in_use(port)
    icp(_result)


@cli.command("internet-available")
@click_add_options(click_global_options)
@click.pass_context
def _internet_available(
    ctx: click.Context,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )

    _result = internet_available()
    icp(_result)


@cli.command("add-alias")
@click.argument("ip_with_subnet", type=str, nargs=1)
@click.argument("device", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _alias_add(
    ctx: click.Context,
    ip_with_subnet: str,
    device: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    try:
        alias_add(ip_with_subnet=ip_with_subnet, device=device)
    except AliasExistsError:
        eprint(f"ERROR: alias {ip_with_subnet} on {device} already exists.")
        sys.exit(1)


@cli.command("delete-alias")
@click.argument("ip_with_subnet", type=str, nargs=1)
@click.argument("device", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _alias_remove(
    ctx: click.Context,
    ip_with_subnet: str,
    device: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    alias_remove(ip_with_subnet=ip_with_subnet, device=device)


@cli.command("link-up")
@click.argument("device", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _link_up(
    ctx: click.Context,
    device: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    set_interface_link_up(device)


@cli.command("link-down")
@click.argument("device", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _link_down(
    ctx: click.Context,
    device: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
) -> None:
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    set_interface_link_down(device)
