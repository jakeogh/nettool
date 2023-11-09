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

from collections.abc import Sequence
from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click
import sh
from asserttool import ic
from click_auto_help import AHGroup
from clicktool import click_add_options
from clicktool import click_global_options
from clicktool import tvicgvd
from globalverbose import gvd
from mptool import output
from unmp import unmp

from nettool import get_default_gateway
from nettool import get_ip_addresses_for_interface
from nettool import get_mac_for_interface
from nettool import tcp_port_in_use

signal(SIGPIPE, SIG_DFL)

sh.mv = None


@click.group(no_args_is_help=True, cls=AHGroup)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
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
    if not verbose:
        ic.disable()


@cli.command("default-gw")
@click.argument("keys", type=str, nargs=-1)
@click_add_options(click_global_options)
@click.pass_context
def _default_gw(
    ctx,
    keys: tuple[str, ...],
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    ctx.ensure_object(dict)
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
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
        # this check could be moved to output() but then we cant exit on error now

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
    ctx,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    ctx.ensure_object(dict)
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
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
        ic(index, _mpobject)
        interface: str = ""
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
    ctx,
    port: int,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )

    _result = tcp_port_in_use(port)
    ic(_result)


@cli.command("add-alias")
@click.argument("ip_with_subnet", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _add_alias(
    ctx,
    ip_with_subnet: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    assert "/" in ip_with_subnet

    sh.ip("address", "add", ip_with_subnet, "dev", "eth0")


@cli.command("delete-alias")
@click.argument("ip_with_subnet", type=str, nargs=1)
@click_add_options(click_global_options)
@click.pass_context
def _delete_alias(
    ctx,
    ip_with_subnet: str,
    verbose_inf: bool,
    dict_output: bool,
    verbose: bool = False,
):
    tty, verbose = tvicgvd(
        ctx=ctx,
        verbose=verbose,
        verbose_inf=verbose_inf,
        ic=ic,
        gvd=gvd,
    )
    assert "/" in ip_with_subnet

    sh.ip("address", "del", ip_with_subnet, "dev", "eth0")
