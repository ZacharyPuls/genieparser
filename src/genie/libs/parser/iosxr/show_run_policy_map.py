import re

from genie.metaparser import MetaParser  # type: ignore
from genie.metaparser.util.schemaengine import Any, Optional, Schema


class ShowRunningConfigPolicyMapSchema(MetaParser):
    """Schema for show running-config policy-map {policy_map}"""

    schema = {
        "policy_map": {
            Any(): {  # Policy-map name as key
                "class": {
                    Any(): {  # Class name as key
                        Optional("police"): {
                            Optional("rate"): {
                                "value": int,
                                "unit": str,  # mbps, kbps, etc.
                            },
                            Optional("burst"): {
                                "value": int,
                                "unit": str,  # kbytes, bytes, etc.
                            },
                            Optional("peak_rate"): {
                                "value": int,
                                "unit": str,  # mbps, kbps, etc.
                            },
                        },
                        Optional("bandwidth"): {
                            "value": int,
                            "unit": str,  # mbps, kbps, etc.
                        },
                        Optional("set"): {
                            Optional("qos_group"): int,
                            Optional("traffic_class"): int,
                            Optional("dscp"): Any(),
                            Optional("precedence"): Any(),
                            # Add other potential 'set' commands as needed
                        },
                        # Add other potential class actions as needed
                    },
                },
            },
        },
    }


class ShowRunningConfigPolicyMap(ShowRunningConfigPolicyMapSchema):
    """Parser for show running-config policy-map {policy_map}"""

    cli_command = [
        "show running-config policy-map {policy_map}",
        "show running-config policy-map",
    ]

    def cli(self, policy_map=None, output=None):
        if output is None:
            if policy_map:
                cmd = self.cli_command[0].format(policy_map=policy_map)
            else:
                cmd = self.cli_command[1]
            output = self.device.execute(cmd)

        # Initialize the result dict
        parsed_dict = {"policy_map": {}}

        # Regular expressions
        policy_map_regex = r"^policy-map\s+(?P<policy_map>\S+)$"
        class_regex = r"^\s*class\s+(?P<class_name>.+)$"
        police_regex = r"^\s*police\s+rate\s+(?P<rate>\d+)\s+(?P<rate_unit>\S+)\s+burst\s+(?P<burst>\d+)\s+(?P<burst_unit>\S+)(?:\s+peak-rate\s+(?P<peak_rate>\d+)\s+(?P<peak_rate_unit>\S+))?"
        bandwidth_regex = r"^\s*bandwidth\s+(?P<value>\d+)\s+(?P<unit>\S+)"
        set_qos_group_regex = r"^\s*set\s+qos-group\s+(?P<value>\d+)$"
        set_traffic_class_regex = r"^\s*set\s+traffic-class\s+(?P<value>\d+)$"
        set_dscp_regex = r"^\s*set\s+dscp\s+(?P<value>\S+)$"
        set_precedence_regex = r"^\s*set\s+precedence\s+(?P<value>\S+)$"

        # Parse the output
        current_policy_map = None
        current_class = None

        for line in output.splitlines():
            line = line.strip()

            # Skip empty lines, comments and section terminators
            if not line or line == "!" or line == "end-policy-map":
                continue

            # Match policy-map line
            match = re.match(policy_map_regex, line)
            if match:
                current_policy_map = match.group("policy_map")
                parsed_dict["policy_map"][current_policy_map] = {"class": {}}
                continue

            # If we haven't matched a policy-map yet, skip
            if not current_policy_map:
                continue

            # Match class line
            match = re.match(class_regex, line)
            if match:
                current_class = match.group("class_name")
                parsed_dict["policy_map"][current_policy_map]["class"][
                    current_class
                ] = {}
                continue

            # If we haven't matched a class yet, skip
            if not current_class:
                continue

            # Match police line
            match = re.match(police_regex, line)
            if match:
                police_dict = {}

                # Always present: rate and burst
                police_dict["rate"] = {
                    "value": int(match.group("rate")),
                    "unit": match.group("rate_unit"),
                }
                police_dict["burst"] = {
                    "value": int(match.group("burst")),
                    "unit": match.group("burst_unit"),
                }

                # Optional: peak-rate
                if match.group("peak_rate"):
                    police_dict["peak_rate"] = {
                        "value": int(match.group("peak_rate")),
                        "unit": match.group("peak_rate_unit"),
                    }

                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "police"
                ] = police_dict
                continue

            # Match bandwidth line
            match = re.match(bandwidth_regex, line)
            if match:
                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "bandwidth"
                ] = {
                    "value": int(match.group("value")),
                    "unit": match.group("unit"),
                }
                continue

            # Match set qos-group line
            match = re.match(set_qos_group_regex, line)
            if match:
                if (
                    "set"
                    not in parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]
                ):
                    parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]["set"] = {}

                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "set"
                ]["qos_group"] = int(match.group("value"))
                continue

            # Match set traffic-class line
            match = re.match(set_traffic_class_regex, line)
            if match:
                if (
                    "set"
                    not in parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]
                ):
                    parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]["set"] = {}

                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "set"
                ]["traffic_class"] = int(match.group("value"))
                continue

            # Match set dscp line
            match = re.match(set_dscp_regex, line)
            if match:
                if (
                    "set"
                    not in parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]
                ):
                    parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]["set"] = {}

                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "set"
                ]["dscp"] = match.group("value")
                continue

            # Match set precedence line
            match = re.match(set_precedence_regex, line)
            if match:
                if (
                    "set"
                    not in parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]
                ):
                    parsed_dict["policy_map"][current_policy_map]["class"][
                        current_class
                    ]["set"] = {}

                parsed_dict["policy_map"][current_policy_map]["class"][current_class][
                    "set"
                ]["precedence"] = match.group("value")
                continue

        return parsed_dict
