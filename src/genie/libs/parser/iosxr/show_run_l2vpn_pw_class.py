import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Schema


class ShowRunningConfigL2vpnPwClassSchema(MetaParser):
    """Schema for show running-config l2vpn pw-class {pwclass_name}"""

    schema = {
        "l2vpn": {
            "pw_classes": {
                Any(): {  # pw-class name as key
                    "encapsulation": {
                        "type": str,
                        Optional("control_word"): bool,  # True if present
                        Optional("preferred_path"): {
                            "type": str,  # interface, etc.
                            "value": str,  # tunnel-te 4011, etc.
                            Optional("fallback"): bool,  # True if fallback enabled
                        },
                    }
                }
            }
        }
    }


class ShowRunningConfigL2vpnPwClass(ShowRunningConfigL2vpnPwClassSchema):
    """Parser for show running-config l2vpn pw-class {pwclass_name}"""

    cli_command = "show running-config l2vpn pw-class {pwclass_name}"

    def cli(self, output=None):
        if output is None:
            cmd = self.cli_command.format(pwclass_name=self.pwclass_name)
            output = self.device.execute(cmd)

        # Initialize the result dict
        parsed_dict = {"l2vpn": {"pw_classes": {}}}

        # Regular expressions
        pw_class_regex = r"^\s*pw-class\s+(?P<pw_class_name>\S+)$"
        encapsulation_regex = r"^\s*encapsulation\s+(?P<encapsulation_type>\S+)$"
        control_word_regex = r"^\s*control-word$"
        preferred_path_regex = r"^\s*preferred-path\s+(?P<path_type>\S+)\s+(?P<path_value>[\w-]+(?:\s+[\d]+)?)(?:\s+fallback\s+(?P<fallback>\S+))?$"

        # Parse the output
        current_pw_class = None
        inside_encapsulation = False

        for line in output.splitlines():
            line = line.strip()

            # Skip empty lines and section terminators
            if not line or line == "!":
                continue

            # Check if line is 'l2vpn', which is the top level and can be skipped
            if line == "l2vpn":
                continue

            # Match pw-class line
            match = re.match(pw_class_regex, line)
            if match:
                current_pw_class = match.group("pw_class_name")
                parsed_dict["l2vpn"]["pw_classes"][current_pw_class] = {}
                inside_encapsulation = False
                continue

            # If we haven't matched a pw-class yet, skip
            if not current_pw_class:
                continue

            # Match encapsulation line
            match = re.match(encapsulation_regex, line)
            if match:
                encapsulation_type = match.group("encapsulation_type")
                parsed_dict["l2vpn"]["pw_classes"][current_pw_class][
                    "encapsulation"
                ] = {"type": encapsulation_type}
                inside_encapsulation = True
                continue

            # If we haven't matched an encapsulation yet, skip
            if not inside_encapsulation:
                continue

            # Match control-word line
            match = re.match(control_word_regex, line)
            if match:
                parsed_dict["l2vpn"]["pw_classes"][current_pw_class]["encapsulation"][
                    "control_word"
                ] = True
                continue

            # Match preferred-path line
            match = re.match(preferred_path_regex, line)
            if match:
                path_type = match.group("path_type")
                path_value = match.group("path_value")
                fallback = match.group("fallback")

                preferred_path = {"type": path_type, "value": path_value}

                if fallback:
                    preferred_path["fallback"] = fallback == "enable"

                parsed_dict["l2vpn"]["pw_classes"][current_pw_class]["encapsulation"][
                    "preferred_path"
                ] = preferred_path
                continue

        return parsed_dict


# Example usage
if __name__ == "__main__":
    # This is just for standalone testing
    from unittest.mock import Mock

    # Example output
    example_output = """
l2vpn
 pw-class PWC-5001000
  encapsulation mpls
   control-word
  !
 !
!

l2vpn
 pw-class PWC-5001002
  encapsulation mpls
   control-word
   preferred-path interface tunnel-te 4011 fallback disable
  !
 !
!
    """

    parser = ShowRunningConfigL2vpnPwClass()
    parsed_output = parser.cli(output=example_output)

    import json

    print(json.dumps(parsed_output, indent=4))
