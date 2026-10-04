"""Parse Nmap XML output into simple Python objects.

This module only READS an Nmap XML file.
It never runs Nmap and never executes commands.
"""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Refuse excessively large input files.
MAX_FILE_BYTES = 20 * 1024 * 1024


class ScanParseError(Exception):
    """Raised when the scan file is empty, malformed, or not Nmap XML."""


@dataclass
class Port:
    """One port reported by Nmap."""

    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""

    @property
    def is_open(self) -> bool:
        """Return True when Nmap reported this port as open."""

        return self.state == "open"


@dataclass
class Host:
    """One scanned host and its ports."""

    ip: str
    hostname: str = ""
    state: str = "unknown"
    ports: list[Port] = field(default_factory=list)

    def open_ports(self) -> list[Port]:
        """Return only the open ports."""

        return [
            port
            for port in self.ports
            if port.is_open
        ]


def _read_scan_file(path: str) -> bytes:
    """Read the scan file with basic safety checks."""

    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Scan file not found: {file_path}"
        )

    size = file_path.stat().st_size

    if size == 0:
        raise ScanParseError(
            "The scan file is empty."
        )

    if size > MAX_FILE_BYTES:
        raise ScanParseError(
            "The scan file is too large "
            "(limit is 20 MB)."
        )

    return file_path.read_bytes()


def _get_ip(host_el: ET.Element) -> str:
    """Return the IPv4 or IPv6 address of a host."""

    for address in host_el.findall("address"):

        if address.get("addrtype") in (
            "ipv4",
            "ipv6",
        ):
            return address.get(
                "addr",
                "",
            )

    return ""


def _get_hostname(host_el: ET.Element) -> str:
    """Return the first hostname, if present."""

    hostname_el = host_el.find(
        "hostnames/hostname"
    )

    if hostname_el is None:
        return ""

    return hostname_el.get(
        "name",
        "",
    )


def _parse_port(
    port_el: ET.Element,
) -> Port | None:
    """Convert one Nmap <port> element into a Port."""

    try:
        number = int(
            port_el.get(
                "portid",
                "",
            )
        )

    except ValueError:

        logger.warning(
            "Skipping a port with an invalid portid."
        )

        return None

    state_el = port_el.find("state")

    state = (
        state_el.get(
            "state",
            "unknown",
        )
        if state_el is not None
        else "unknown"
    )

    protocol = port_el.get(
        "protocol",
        "",
    )

    service_el = port_el.find(
        "service"
    )

    # A service element is not guaranteed to exist.
    if service_el is None:

        return Port(
            number=number,
            protocol=protocol,
            state=state,
        )

    return Port(
        number=number,
        protocol=protocol,
        state=state,
        service=service_el.get(
            "name",
            "",
        ),
        product=service_el.get(
            "product",
            "",
        ),
        version=service_el.get(
            "version",
            "",
        ),
        extrainfo=service_el.get(
            "extrainfo",
            "",
        ),
    )


def _parse_host(
    host_el: ET.Element,
) -> Host | None:
    """Convert one Nmap <host> element into a Host."""

    ip = _get_ip(host_el)

    if not ip:

        logger.warning(
            "Skipping a host without an IP address."
        )

        return None

    status_el = host_el.find("status")

    state = (
        status_el.get(
            "state",
            "unknown",
        )
        if status_el is not None
        else "unknown"
    )

    host = Host(
        ip=ip,
        hostname=_get_hostname(
            host_el
        ),
        state=state,
    )

    for port_el in host_el.findall(
        "ports/port"
    ):

        port = _parse_port(
            port_el
        )

        if port is not None:
            host.ports.append(port)

    return host


def parse_nmap_xml(
    path: str,
) -> list[Host]:
    """Parse an Nmap XML scan file."""

    data = _read_scan_file(path)

    # Real Nmap XML does not need entity declarations.
    # Reject them because the scan file is untrusted input.
    if b"<!ENTITY" in data.upper():

        raise ScanParseError(
            "XML entity declarations are not allowed."
        )

    try:

        root = ET.fromstring(data)

    except ET.ParseError as err:

        raise ScanParseError(
            f"Malformed XML: {err}"
        ) from err

    if root.tag != "nmaprun":

        raise ScanParseError(
            "This does not look like an Nmap XML file "
            "(root element must be <nmaprun>)."
        )

    hosts: list[Host] = []

    for host_el in root.findall("host"):

        host = _parse_host(
            host_el
        )

        if host is not None:
            hosts.append(host)

    return hosts
