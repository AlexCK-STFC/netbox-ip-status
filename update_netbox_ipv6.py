#!/bin/env python3

import argparse
import glob
import json
import logging
import xml.etree.ElementTree as ET
from configparser import ConfigParser
from dataclasses import dataclass
from typing import cast
from urllib.parse import urljoin

import traceback

import coloredlogs
import pynetbox
import requests
from pynetbox.models.dcim import Devices, Interfaces
from pynetbox.models.ipam import IpAddresses
from pynetbox.models.virtualization import VirtualMachines

from ipaddress import IPv6Network
from rich import print

@dataclass(frozen=True)
class IPv6Binding:
    hostname: str
    interface: str
    address: IPv6Network


class UpdateNetboxIPv6:
    def __init__(self, source: str, nb_url: str, nb_token: str):
        self.nb = pynetbox.api(url=nb_url, token=nb_token)
        self.ipv6_aquilon = set()
        self.ipv6_netbox = set()

        if source == "aquilon":
            self.profiles = self.load_profiles_aquilon()
        else:
            self.profiles = self.load_profiles_xml(source)

        for profile in self.profiles:
            profile_ipv6_aq = self.get_ipv6_aquilon(profile)
            profile_ipv6_nb = self.get_ipv6_netbox(profile)
            if profile_ipv6_aq or profile_ipv6_nb:
                print("Profile: ", profile["filename"])
                # print(f"AQ Interfaces: {profile_ipv6_aq}")
                # print(f"NB Interfaces: {profile_ipv6_nb}")
                if profile_ipv6_aq == profile_ipv6_nb:
                    print("[green]Already Correct![/green]")
                else:
                    intersect = profile_ipv6_aq & profile_ipv6_nb
                    print(f"[yellow]Difference: {profile_ipv6_aq - profile_ipv6_nb}[/yellow]")
                    if intersect:
                        print(f"[green]Intersection: {intersect}[/green]")
                print("========")
                self.ipv6_aquilon |= profile_ipv6_aq
                self.ipv6_netbox |= profile_ipv6_nb

    def load_profiles_xml(self, base_url: str):
        url = urljoin(base_url.rstrip("/") + "/", "profiles-info.xml")

        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            root = ET.fromstring(r.content)

            for item in root.findall("profile"):
                filename = (item.text or "").strip()
                if not filename:
                    continue

                json_url = urljoin(base_url.rstrip("/") + "/", filename)

                jr = requests.get(json_url, timeout=10)
                jr.raise_for_status()

                yield json.loads(jr.content)

        except requests.RequestException as e:
            raise RuntimeError("Failed to fetch XML") from e

        except ET.ParseError as e:
            raise RuntimeError("Invalid XML returned") from e

        except json.JSONDecodeError as e:
            raise RuntimeError("Profile JSON failed to decode") from e

    def load_profiles_aquilon(self):
        GLOB_PROFILES = "/var/quattor/web/htdocs/profiles/*.json"
        for filename in glob.glob(GLOB_PROFILES):
            with open(filename) as file_handle:
                profile = json.load(file_handle)
                profile["filename"] = filename
                yield profile

    def get_ipv6_addresses_from_netbox_interface(
        self,
        interface: Interfaces,
    ) -> list[IpAddresses]:
        if interface.count_ipaddresses == 0:
            return []

        if hasattr(interface, "device"):
            all_addresses = self.nb.ipam.ip_addresses.filter(interface_id=interface.id)
        elif hasattr(interface, "virtual_machine"):
            all_addresses = self.nb.ipam.ip_addresses.filter(
                vminterface_id=interface.id
            )
        else:
            return []

        ipv6_addresses = []
        for address in all_addresses:
            if address.family.value == 6:
                ipv6_addresses.append(address)
            else:
                logging.debug(
                    "Skipped interface %s address (%s) since it is not IPV6, it is %s",
                    interface.name,
                    address.address,
                    address.family.label,
                )

        return ipv6_addresses

    def get_ipv6_netbox(self, profile_data: dict) -> set[IPv6Binding]:
        is_vm = (
            "type" in profile_data["hardware"]
            and profile_data["hardware"]["type"] == "virtual_machine"
        )

        ipv6_addresses = set()
        profile_interfaces = profile_data["system"]["network"]["interfaces"]
        hostname = (
            profile_data["system"]["network"]["hostname"]
            + "."
            + profile_data["system"]["network"]["domainname"]
        )

        for interface_name, profile_interface in profile_interfaces.items():
            mac = "null"
            if interface_name in profile_data["hardware"]["cards"]["nic"]:
                mac = profile_data["hardware"]["cards"]["nic"][interface_name]["hwaddr"]

            if is_vm:
                netbox_interfaces = self.nb.virtualization.interfaces.filter(
                    name=interface_name, mac_address=mac
                )
                if not netbox_interfaces:
                    primary_ip = profile_data["system"]["network"]["primary_ip"]
                    netbox_ip = cast(
                        IpAddresses, self.nb.ipam.ip_addresses.get(address=primary_ip)
                    )
                    if netbox_ip is None:
                        logging.warning(f"{interface_name} for {hostname} has IP {primary_ip} which mapped to a netbox None")
                        continue
                    netbox_primary_interface = cast(
                        Interfaces, netbox_ip.assigned_object
                    )
                    netbox_device = cast(
                        VirtualMachines, netbox_primary_interface.virtual_machine
                    )
                    netbox_interfaces = self.nb.virtualization.interfaces.filter(
                        name=interface_name, virtual_machine_id=netbox_device.id
                    )
            else:
                netbox_interfaces = self.nb.dcim.interfaces.filter(
                    name=interface_name, mac_address=mac
                )
                if not netbox_interfaces:
                    primary_ip = profile_data["system"]["network"]["primary_ip"]
                    netbox_ip = cast(
                        IpAddresses, self.nb.ipam.ip_addresses.get(address=primary_ip)
                    )
                    if netbox_ip is None:
                        logging.warning(f"{interface_name} for {hostname} has IP {primary_ip} which mapped to a netbox None")
                        continue
                    netbox_primary_interface = cast(
                        Interfaces, netbox_ip.assigned_object
                    )
                    netbox_device = cast(Devices, netbox_primary_interface.device)
                    netbox_interfaces = self.nb.virtualization.interfaces.filter(
                        name=interface_name, device_id=netbox_device.id
                    )

            for netbox_interface in netbox_interfaces:
                ads = self.get_ipv6_addresses_from_netbox_interface(netbox_interface)
                for addr in ads:
                    ipv6_addresses.add(
                        IPv6Binding(
                            hostname=hostname,
                            interface=interface_name,
                            address=IPv6Network(addr.address, strict=False)),
                        )

        return ipv6_addresses

    def get_ipv6_aquilon(self, profile_data: dict) -> set[IPv6Binding]:
        ipv6_addresses = set()
        if "ipv6" not in profile_data["system"]["network"]:
            return ipv6_addresses

        if not profile_data["system"]["network"]["ipv6"]["enabled"]:
            return ipv6_addresses

        print("========")
        # print("Found IPv6")
        print("#", profile_data["hardware"]["nodename"])

        profile_interfaces = profile_data["system"]["network"]["interfaces"]
        hostname = (
            profile_data["system"]["network"]["hostname"]
            + "."
            + profile_data["system"]["network"]["domainname"]
        )

        for interface_name, profile_interface in profile_interfaces.items():
            if "ipv6addr" in profile_interface:
                # mac = "null"
                # if interface_name in profile_data["hardware"]["cards"]["nic"]:
                #     mac = profile_data["hardware"]["cards"]["nic"][interface_name]["hwaddr"]
                ipv6addr = profile_interface["ipv6addr"]
                ipv6_addresses.add(
                    IPv6Binding(
                        hostname=hostname, interface=interface_name, address=IPv6Network(ipv6addr, strict=False)
                    )
                )

        return ipv6_addresses


def main():
    logging.basicConfig(format="%(levelname)s: %(message)s")
    coloredlogs.install(fmt="%(levelname)7s: %(message)s")

    config = ConfigParser()
    config.read(["netbox_ip_status.cfg.default", "netbox_ip_status.cfg"])

    parser = argparse.ArgumentParser()

    aquilon_arg_group = parser.add_argument_group(
        "Aquilon Datasource",
        "Run locally, or fetch from Aquilon via profiles served by the broker's HTTP server",
    )
    source_group = aquilon_arg_group.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        "--local", action="store_true", help="Use Aquilon local configuration"
    )

    source_group.add_argument(
        "--profiles-url-base-path",
        type=str,
        help="""Base URL path for aquilon profiles
        I.e. https://example.org/profiles/""",
    )

    args = parser.parse_args()

    if args.local:
        source = "aquilon"
    else:
        source = args.profiles_url_base_path

    ipv6_obj = UpdateNetboxIPv6(
        source=source,
        nb_url=config["NETBOX"]["URL"],
        nb_token=config["NETBOX"]["API_KEY"],
    )

    print("Done!")

    # print("Debug:")

    # print(ipv6_obj.ipv6_aquilon)
    # print(ipv6_obj.ipv6_netbox)

    # print(f"Difference: {ipv6_obj.ipv6_aquilon - ipv6_obj.ipv6_netbox}")
    # print(f"Intersection: {ipv6_obj.ipv6_aquilon & ipv6_obj.ipv6_netbox}")

    

    # if opts.debug:
    #    coloredlogs.set_level(logging.DEBUG)


if __name__ == "__main__":
    main()
