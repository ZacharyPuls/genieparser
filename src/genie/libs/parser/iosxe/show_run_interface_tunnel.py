import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Schema


class ShowRunningConfigInterfaceTunnelSchema(MetaParser):
    """Schema for show running-config interface Tunnel{tunnel_id}"""

    schema = {
        Optional("interfaces"): {
            Any(): {  # Interface name as key (e.g., 'Tunnel3002')
                Optional("description"): str,
                Optional("source"): str,
                Optional("destination"): str,
                Optional("tunnel_mode"): str,
                Optional(
                    "path_protection"
                ): bool,  # For compatibility with the IOS-XR model
                Optional("path_options"): {
                    Any(): {  # Index as key
                        "type": str,  # 'explicit', 'dynamic'
                        Optional("name"): str,  # Path option name
                        Optional("protect"): str,  # Protect path-option name
                    },
                },
            },
        },
    }


class ShowRunningConfigInterfaceTunnel(ShowRunningConfigInterfaceTunnelSchema):
    """Parser for show running-config interface Tunnel{tunnel_id}"""

    cli_command = [
        "show running-config interface Tunnel{tunnel_id}",
        "show running-config | section ^interface Tunnel",
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
        interface_regex = r"^interface\s+(?P<interface>Tunnel\d+)$"
        description_regex = r"^\s*description\s+(?P<description>.+)$"
        ip_unnumbered_regex = r"^\s*ip\s+unnumbered\s+(?P<source>\S+)$"
        tunnel_mode_regex = r"^\s*tunnel\s+mode\s+(?P<tunnel_mode>\S+)$"
        destination_regex = r"^\s*tunnel\s+destination\s+(?P<destination>[\d\.]+)$"
        path_option_regex = r"^\s*tunnel\s+mpls\s+traffic-eng\s+path-option\s+(?P<protect>protect)?\s*(?P<priority>\d+)\s+(?P<type>\S+)(?:\s+name\s+(?P<name>[^\s]+))?"

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

            # Match ip unnumbered
            match = re.match(ip_unnumbered_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["source"] = match.group(
                    "source"
                )
                continue

            # Match tunnel mode
            match = re.match(tunnel_mode_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["tunnel_mode"] = (
                    match.group("tunnel_mode")
                )
                continue

            # Match destination
            match = re.match(destination_regex, line)
            if match:
                parsed_dict["interfaces"][current_interface]["destination"] = (
                    match.group("destination")
                )
                continue

            # Match path-option
            match = re.match(path_option_regex, line)
            if match:
                priority = match.group("priority")
                path_type = match.group("type")
                name = match.group("name")
                protect = match.group("protect")

                if "path_options" not in parsed_dict["interfaces"][current_interface]:
                    parsed_dict["interfaces"][current_interface]["path_options"] = {}

                if protect:
                    parsed_dict["interfaces"][current_interface]["path_options"][
                        priority
                    ]["protect"] = name
                    parsed_dict["interfaces"][current_interface][
                        "path_protection"
                    ] = True
                    continue

                parsed_dict["interfaces"][current_interface]["path_options"][
                    priority
                ] = {"type": path_type}

                if name:
                    parsed_dict["interfaces"][current_interface]["path_options"][
                        priority
                    ]["name"] = name

                continue

        return parsed_dict
