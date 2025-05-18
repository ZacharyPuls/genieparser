import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Or, Schema


class ShowRunningConfigClassMapSchema(MetaParser):
    """
    Schema for show running-config class-map {class_map_name}
    """

    schema = {
        "class_map": {
            Any(): {
                "match_type": str,
                Optional("match_conditions"): [
                    Or(
                        {
                            "type": "access-group",
                            "name": str,
                        },
                        {
                            "type": "cos",
                            "value": int,
                        },
                        {
                            "type": "qos-group",
                            "value": int,
                        },
                        {
                            "type": "mpls_experimental_topmost",
                            "value": int,
                        },
                    )
                ],
            }
        }
    }


class ShowRunningConfigClassMap(ShowRunningConfigClassMapSchema):
    """
    Parser for show running-config class-map {class_map_name}
    """

    cli_command = [
        "show running-config class-map {class_map_name}",
        "show running-config class-map",
    ]

    def cli(self, class_map_name=None, output=None):
        if output is None:
            if class_map_name:
                cmd = self.cli_command[0].format(explicit_path_name=class_map_name)
            else:
                cmd = self.cli_command[1]
            output = self.device.execute(cmd)

        parsed_dict = {}

        # class-map match-all CLASS-BROADCAST-INGRESS
        p_class_map = re.compile(
            r"^\s*class-map\s+(?P<match_type>\S+)\s+(?P<class_map_name>\S+)\s*$"
        )

        # match access-group name BROADCAST
        p_match_access_group = re.compile(
            r"^\s*match\s+access-group\s+name\s+(?P<name>\S+)\s*$"
        )

        # match cos  7
        p_match_cos = re.compile(r"^\s*match\s+cos\s+(?P<value>\d+)\s*$")

        # match qos-group 20
        p_match_qos_group = re.compile(r"^\s*match\s+qos-group\s+(?P<value>\d+)\s*$")

        # match mpls experimental topmost 0
        p_match_mpls_exp = re.compile(
            r"^\s*match\s+mpls\s+experimental\s+topmost\s+(?P<value>\d+)\s*$"
        )

        current_class_map_name = None
        class_map_entry = {}

        for line in output.splitlines():
            line = line.strip()

            if (
                not line
                or line == "!"
                or line == "end"
                or line.startswith("Building configuration...")
                or line.startswith("Current configuration :")
            ):
                continue

            m_cm = p_class_map.match(line)
            if m_cm:
                group = m_cm.groupdict()
                current_class_map_name = group["class_map_name"]
                match_type = group["match_type"]

                if "class_map" not in parsed_dict:
                    parsed_dict["class_map"] = {}

                class_map_entry = parsed_dict["class_map"].setdefault(
                    current_class_map_name, {}
                )
                class_map_entry["match_type"] = match_type
                class_map_entry.setdefault("match_conditions", [])
                continue

            if not current_class_map_name:
                continue

            if current_class_map_name not in parsed_dict.get("class_map", {}):
                continue

            active_class_map_data = parsed_dict["class_map"][current_class_map_name]

            m_ag = p_match_access_group.match(line)
            if m_ag:
                group = m_ag.groupdict()
                active_class_map_data["match_conditions"].append(
                    {"type": "access-group", "name": group["name"]}
                )
                continue

            m_cos = p_match_cos.match(line)
            if m_cos:
                group = m_cos.groupdict()
                active_class_map_data["match_conditions"].append(
                    {"type": "cos", "value": int(group["value"])}
                )
                continue

            m_qos = p_match_qos_group.match(line)
            if m_qos:
                group = m_qos.groupdict()
                active_class_map_data["match_conditions"].append(
                    {"type": "qos-group", "value": int(group["value"])}
                )
                continue

            m_mpls = p_match_mpls_exp.match(line)
            if m_mpls:
                group = m_mpls.groupdict()
                active_class_map_data["match_conditions"].append(
                    {"type": "mpls_experimental_topmost", "value": int(group["value"])}
                )
                continue

        return parsed_dict
