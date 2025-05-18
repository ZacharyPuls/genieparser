import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Schema


class ShowRunningConfigExplicitPathSchema(MetaParser):
    """Schema for show running-config | section ^ip explicit-path name {explicit_path_name}"""

    schema = {
        "explicit_paths": {
            Any(): {  # Explicit path name as key
                "indexes": {
                    Any(): {  # Index number as key
                        "type": str,  # 'strict', 'loose'
                        "address": str,
                    },
                },
            },
        },
    }


class ShowRunningConfigExplicitPath(ShowRunningConfigExplicitPathSchema):
    """Parser for show running-config | section ^ip explicit-path name {explicit_path_name}"""

    cli_command = [
        "show running-config | section ^ip explicit-path name {explicit_path_name}",
        "show running-config | section ^ip explicit-path",
    ]

    def cli(self, explicit_path_name=None, output=None):
        if output is None:
            if explicit_path_name:
                cmd = self.cli_command[0].format(explicit_path_name=explicit_path_name)
            else:
                cmd = self.cli_command[1]
            output = self.device.execute(cmd)

        # Initialize the result dict
        parsed_dict = {"explicit_paths": {}}

        # Regular expressions
        explicit_path_regex = (
            r"^ip\s+explicit-path\s+name\s+(?P<path_name>\S+)\s+enable$"
        )
        index_regex = r"^\s*index\s+(?P<index>\d+)\s+next-address\s+(?P<loose>loose)?\s*(?P<address>[\d\.]+)$"

        # Parse the output
        current_path = None

        for line in output.splitlines():
            line = line.strip()

            # Skip empty lines and section terminators
            if not line or line == "!":
                continue

            # Match explicit-path line
            match = re.match(explicit_path_regex, line)
            if match:
                current_path = match.group("path_name")
                parsed_dict["explicit_paths"][current_path] = {"indexes": {}}
                continue

            # If we haven't matched an explicit-path yet, skip
            if not current_path:
                continue

            # Match index line
            match = re.match(index_regex, line)
            if match:
                index = match.group("index")
                loose = match.group("loose")
                address = match.group("address")

                parsed_dict["explicit_paths"][current_path]["indexes"][index] = {
                    "type": "loose" if loose else "strict",
                    "address": address,
                }
                continue

        return parsed_dict
