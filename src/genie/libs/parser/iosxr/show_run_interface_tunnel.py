import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Schema


class ShowRunningConfigInterfaceTunnelTeSchema(MetaParser):
    """Schema for show running-config interface tunnel-te {tunnel_id}"""

    schema = {
        Optional("interfaces"): {
            Any(): {  # Interface name as key (e.g., 'tunnel-te3002')
                Optional("description"): str,
                Optional("ipv4"): {
                    Optional("unnumbered"): str,
                },
                Optional("destination"): str,
                Optional("path_protection"): bool,
                Optional("path_options"): {
                    Any(): {  # Index as key
                        "type": str,  # 'explicit', 'dynamic'
                        Optional("name"): str,  # Path option name
                        Optional("protected_by"): str,  # Protected by index
                    },
                },
            },
        },
    }


class ShowRunningConfigInterfaceTunnelTe(ShowRunningConfigInterfaceTunnelTeSchema):
    """Parser for show running-config interface tunnel-te {tunnel_id}"""

    cli_command = [
        "show running-config interface tunnel-te {tunnel_id}",
        "show running-config interface tunnel-te *",
    ]

    def cli(self, tunnel_id=None, output=None):
        if output is None:
            if tunnel_id:
                cmd = self.cli_command[0].format(tunnel_id=tunnel_id)
            else:
                cmd = self.cli_command[1]
            output = self.device.execute(cmd)

        # Initialize the result dict
        parsed_dict = {"interfaces": {}}

        # Regular expressions
        interface_regex = r"^interface\s+(?P<interface>tunnel-te\d+)$"
        description_regex = r"^\s*description\s+(?P<description>.+)$"
        ipv4_unnumbered_regex = r"^\s*ipv4\s+unnumbered\s+(?P<interface>\S+)$"
        destination_regex = r"^\s*destination\s+(?P<destination>[\d\.]+)$"
        path_protection_regex = r"^\s*path-protection$"
        path_option_regex = r"^\s*path-option\s+(?P<priority>\d+)\s+(?P<type>\S+)(?:\s+name\s+(?P<name>[^\s]+))?(?:\s+protected-by\s+(?P<protected_by>\d+))?"

        # Parse the output
        current_interface = None

        for line in output.splitlines():
            line = line.strip()

            # Skip empty lines and section terminators
            if not line or line == "!":
                continue

            # Match interface line
            match = re.match(interface_regex, line)
            if match:
                current_interface = match.group("interface")
                parsed_dict["interfaces"][current_interface] = {}
                continue

            # If we haven't matched an interface yet, skip
            if not current_interface:
                continue

            # Match description
            match = re.match(description_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["description"] = (
                    match.group("description")
                )
                continue

            # Match ipv4 unnumbered
            match = re.match(ipv4_unnumbered_regex, line)
            if match:
                if "ipv4" not in parsed_dict["interfaces"][current_interface]:
                    parsed_dict["interfaces"][current_interface]["ipv4"] = {}
                parsed_dict["interfaces"][current_interface]["ipv4"]["unnumbered"] = (
                    match.group("interface")
                )
                continue

            # Match destination
            match = re.match(destination_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["destination"] = (
                    match.group("destination")
                )
                continue

            # Match path-protection
            match = re.match(path_protection_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["path_protection"] = True
                continue

            # Match path-option
            match = re.match(path_option_regex, line)
            if match:
                priority = match.group("priority")
                path_type = match.group("type")
                name = match.group("name")
                protected_by = match.group("protected_by")

                if "path_options" not in parsed_dict["interfaces"][current_interface]:
                    parsed_dict["interfaces"][current_interface]["path_options"] = {}

                parsed_dict["interfaces"][current_interface]["path_options"][
                    priority
                ] = {"type": path_type}

                if name:
                    parsed_dict["interfaces"][current_interface]["path_options"][
                        priority
                    ]["name"] = name

                if protected_by:
                    parsed_dict["interfaces"][current_interface]["path_options"][
                        priority
                    ]["protected_by"] = protected_by

                continue

        return parsed_dict
