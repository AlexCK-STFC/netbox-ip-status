#!/bin/env python3

import argparse
import glob
import json
import logging
import xml.etree.ElementTree as ET
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv6Network
from typing import Callable, Generic, Iterator, Optional, TypeVar
from urllib.parse import urljoin

import coloredlogs
import pynetbox
import requests
from rich import print


@dataclass(frozen=True)
class IPv6Binding:
    hostname: str
    interface: str
    address: IPv6Network


T = TypeVar("T")


class Profiles(Generic[T]):
    def __init__(self, length: int, gen_func: Callable[[], Iterator[T]]):
        self._length = length
        self._gen_func = gen_func

    def __len__(self) -> int:
        return self._length

    def __iter__(self) -> Iterator[T]:
        return self._gen_func()


class UpdateNetboxIPv6:
    def __init__(
        self,
        source: str,
        nb_url: str,
        nb_token: str,
        archetype: Optional[str],
        personality: Optional[str],
    ):
        self.nb = pynetbox.api(url=nb_url, token=nb_token)
        self.ipv6_aquilon = set()
        self.ipv6_netbox = set()

        self._ip_to_device = {}
        self._mac_to_device = {}
        self._device_ips_cache = {}

        if source == "aquilon":
            self.profiles = self.load_profiles_aquilon(
                archetype=archetype, personality=personality
            )
        else:
            self.profiles = self.load_profiles_xml(
                source, archetype=archetype, personality=personality
            )

        for i, profile in enumerate(self.profiles):
            profile_ipv6_aq = self.get_ipv6_aquilon(profile)
            profile_ipv6_nb = self.get_ipv6_netbox(profile)

            if profile_ipv6_aq or profile_ipv6_nb:
                print(f"Profile {i}/{len(self.profiles)}: {profile['filename']}")
                if profile_ipv6_aq == profile_ipv6_nb:
                    print("[green]Already Correct![/green]")
                else:
                    intersect = profile_ipv6_aq & profile_ipv6_nb
                    print(
                        f"[yellow]Difference: {profile_ipv6_aq - profile_ipv6_nb}[/yellow]"
                    )
                    if intersect:
                        print(f"[green]Intersection: {intersect}[/green]")
                print("========")
                self.ipv6_aquilon |= profile_ipv6_aq
                self.ipv6_netbox |= profile_ipv6_nb

    def load_profiles_xml(
        self, base_url: str, archetype: Optional[str], personality: Optional[str]
    ):
        url = urljoin(base_url.rstrip("/") + "/", "profiles-info.xml")

        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            root = ET.fromstring(r.content)

            filenames = [
                (item.text or "").strip()
                for item in root.findall("profile")
                if (item.text or "").strip()
            ]

            def _gen() -> Iterator[dict]:
                for filename in filenames:
                    json_url = urljoin(base_url.rstrip("/") + "/", filename)
                    jr = requests.get(json_url, timeout=10)
                    jr.raise_for_status()

                    profile = json.loads(jr.content)

                    if (
                        archetype
                        and profile["system"]["archetype"]["name"] != archetype
                    ):
                        continue
                    if (
                        personality
                        and profile["system"]["personality"]["name"] != personality
                    ):
                        continue

                    yield profile

            return Profiles(len(filenames), _gen)

        except requests.RequestException as e:
            raise RuntimeError("Failed to fetch XML") from e
        except ET.ParseError as e:
            raise RuntimeError("Invalid XML returned") from e
        except json.JSONDecodeError as e:
            raise RuntimeError("Profile JSON failed to decode") from e

    def load_profiles_aquilon(
        self, archetype: Optional[str], personality: Optional[str]
    ):
        GLOB_PROFILES = "/var/quattor/web/htdocs/profiles/*.json"
        filenames = glob.glob(GLOB_PROFILES)

        def _gen() -> Iterator[dict]:
            for filename in filenames:
                with open(filename) as file_handle:
                    profile = json.load(file_handle)

                profile["filename"] = filename

                if archetype and profile["system"]["archetype"]["name"] != archetype:
                    continue
                if (
                    personality
                    and profile["system"]["personality"]["name"] != personality
                ):
                    continue

                yield profile

        return Profiles(len(filenames), _gen)

    def _get_netbox_device_id(
        self, primary_ip: str, profile_interfaces: dict, profile_data: dict, is_vm: bool
    ):
        """Finds the NetBox device ID using Primary IP (fast) or MAC address (fallback)."""

        # 1. Check IP Cache
        if primary_ip and primary_ip in self._ip_to_device:
            return self._ip_to_device[primary_ip]

        # 2. Try to find Device via Primary IP (1 API Call)
        # We use .filter instead of .get because IP duplicates (e.g., VRFs) crash .get()
        if primary_ip:
            nb_ips = self.nb.ipam.ip_addresses.filter(address=primary_ip)
            for nb_ip in nb_ips:
                assigned_obj = nb_ip.assigned_object
                if assigned_obj:
                    if (
                        is_vm
                        and hasattr(assigned_obj, "virtual_machine")
                        and assigned_obj.virtual_machine
                    ):
                        dev_id = assigned_obj.virtual_machine.id
                        self._ip_to_device[primary_ip] = dev_id
                        return dev_id
                    elif (
                        not is_vm
                        and hasattr(assigned_obj, "device")
                        and assigned_obj.device
                    ):
                        dev_id = assigned_obj.device.id
                        self._ip_to_device[primary_ip] = dev_id
                        return dev_id

        # 3. Fallback: Try finding via MAC addresses
        for interface_name, _ in profile_interfaces.items():
            mac = (
                profile_data.get("hardware", {})
                .get("cards", {})
                .get("nic", {})
                .get(interface_name, {})
                .get("hwaddr")
            )
            if mac and mac != "null":
                if mac in self._mac_to_device:
                    return self._mac_to_device[mac]

                if is_vm:
                    nb_intfs = self.nb.virtualization.interfaces.filter(mac_address=mac)
                    for intf in nb_intfs:
                        if hasattr(intf, "virtual_machine") and intf.virtual_machine:
                            dev_id = intf.virtual_machine.id
                            self._mac_to_device[mac] = dev_id
                            return dev_id
                else:
                    nb_intfs = self.nb.dcim.interfaces.filter(mac_address=mac)
                    for intf in nb_intfs:
                        if hasattr(intf, "device") and intf.device:
                            dev_id = intf.device.id
                            self._mac_to_device[mac] = dev_id
                            return dev_id
        return None

    def _get_device_ips(self, is_vm: bool, dev_id: int):
        """Fetches all IPs assigned to a device/VM in a single API call."""
        cache_key = (is_vm, dev_id)
        if cache_key in self._device_ips_cache:
            return self._device_ips_cache[cache_key]

        if is_vm:
            ips = list(self.nb.ipam.ip_addresses.filter(virtual_machine_id=dev_id))
        else:
            ips = list(self.nb.ipam.ip_addresses.filter(device_id=dev_id))

        self._device_ips_cache[cache_key] = ips
        return ips

    def get_ipv6_netbox(self, profile_data: dict) -> set[IPv6Binding]:
        is_vm = (
            "type" in profile_data.get("hardware", {})
            and profile_data["hardware"]["type"] == "virtual_machine"
        )
        ipv6_addresses = set()

        network_data = profile_data.get("system", {}).get("network", {})
        profile_interfaces = network_data.get("interfaces", {})

        hostname = f"{network_data.get('hostname')}.{network_data.get('domainname')}"
        primary_ip = network_data.get("primary_ip")

        # Step 1: Resolve the Host to a NetBox Device/VM ID
        netbox_device_id = self._get_netbox_device_id(
            primary_ip, profile_interfaces, profile_data, is_vm
        )

        if not netbox_device_id:
            logging.warning(
                f"Could not map {hostname} to a NetBox device/VM (tried IP {primary_ip} and MACs)"
            )
            return ipv6_addresses

        # Step 2: Fetch ALL IP records for that Device/VM
        device_ips = self._get_device_ips(is_vm, netbox_device_id)

        # Step 3: Map in-memory without further API calls
        for address in device_ips:
            if address.family.value == 6:
                assigned_obj = address.assigned_object
                if assigned_obj and hasattr(assigned_obj, "name"):
                    nb_intf_name = assigned_obj.name

                    # Only bind if the NetBox interface name exists in our Aquilon profile
                    if nb_intf_name in profile_interfaces:
                        ipv6_addresses.add(
                            IPv6Binding(
                                hostname=hostname,
                                interface=nb_intf_name,
                                address=IPv6Network(address.address, strict=False),
                            )
                        )
                else:
                    logging.debug(
                        f"Skipped {address.address} for {hostname} - no valid assigned interface name."
                    )

        return ipv6_addresses

    def get_ipv6_aquilon(self, profile_data: dict) -> set[IPv6Binding]:
        ipv6_addresses = set()
        network_data = profile_data.get("system", {}).get("network", {})

        if "ipv6" not in network_data or not network_data["ipv6"].get("enabled"):
            return ipv6_addresses

        print("========")
        print("#", profile_data["hardware"]["nodename"])

        profile_interfaces = network_data.get("interfaces", {})
        hostname = f"{network_data.get('hostname')}.{network_data.get('domainname')}"

        for interface_name, profile_interface in profile_interfaces.items():
            if "ipv6addr" in profile_interface:
                ipv6addr = profile_interface["ipv6addr"]
                ipv6_addresses.add(
                    IPv6Binding(
                        hostname=hostname,
                        interface=interface_name,
                        address=IPv6Network(ipv6addr, strict=False),
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

    parser.add_argument("--archetype", type=str, help="Aquilon Archetype to limit to")
    parser.add_argument(
        "--personality", type=str, help="Aquilon Personality to limit to"
    )

    args = parser.parse_args()

    if args.local:
        source = "aquilon"
    else:
        source = args.profiles_url_base_path

    if args.archetype:
        logging.info(f"Limiting scope to aquilon archetype <{args.archetype}>")

    if args.personality:
        logging.info(f"Limiting scope to aquilon personality <{args.personality}>")

    UpdateNetboxIPv6(
        source=source,
        nb_url=config["NETBOX"]["URL"],
        nb_token=config["NETBOX"]["API_KEY"],
        archetype=args.archetype,
        personality=args.personality,
    )

    print("Done!")


if __name__ == "__main__":
    main()
