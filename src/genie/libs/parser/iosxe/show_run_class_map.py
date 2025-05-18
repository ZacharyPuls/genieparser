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
                Optional("access_group"): str,
                Optional("cos"): int,
                Optional("discard_class"): str,
                Optional("dscp"): Or(int, str),
                Optional("group_object"): {
                    Optional("source"): str,
                    Optional("destination"): str,
                },
                Optional("ip"): str,
                Optional("mpls_experimental_topmost"): int,
                Optional("precedence"): int,
                Optional("qos_group"): int,
                Optional("service_instance"): int,
                Optional("vlan"): {
                    "id": int,
                    Optional("inner"): bool,
                },
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
        if not output:
            if class_map_name:
                cmd = self.cli_command[0].format(class_map_name=class_map_name)
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
        # match discard-class 7
        p_match_discard_class = re.compile(
            r"^\s*match\s+discard-class\s+(?P<value>\S+)\s*$"
        )
        # match dscp ef
        # match ip dscp ef
        # match dscp 0
        p_match_dscp = re.compile(r"^\s*match\s+(?:ip\s+)?dscp\s+(?P<value>\S+)\s*$")

        # match group-object security source GROUP
        p_match_group_object_source = re.compile(
            r"^\s*match\s+group-object\s+(?:\S+\s+)?source\s+(?P<name>\S+)\s*$"
        )
        # match group-object security destination TEST
        p_match_group_object_destination = re.compile(
            r"^\s*match\s+group-object\s+(?:\S+\s+)?destination\s+(?P<name>\S+)\s*$"
        )
        # match ip address MY_ACL
        p_match_ip = re.compile(r"^\s*match\s+ip\s+(?P<value>\S+)\s*$")

        # match mpls experimental topmost 0
        p_match_mpls_exp = re.compile(
            r"^\s*match\s+mpls\s+experimental\s+topmost\s+(?P<value>\d+)\s*$"
        )

        # match precedence 7
        # match ip precedence 7
        p_match_precedence = re.compile(
            r"^\s*match\s+(?:ip\s+)?precedence\s+(?P<value>\S+)\s*$"
        )

        # match qos-group 20
        p_match_qos_group = re.compile(r"^\s*match\s+qos-group\s+(?P<value>\d+)\s*$")

        # match service instance ethernet 283
        p_match_service_instance = re.compile(
            r"^\s*match\s+service\s+instance\s+(?:\S+\s+)?(?P<id>\d+)\s*$"
        )

        # match vlan 1382
        p_match_vlan_id = re.compile(r"^\s*match\s+vlan\s+(?P<id>\d+)\s*$")
        # match vlan inner 1839
        p_match_vlan_id_inner = re.compile(
            r"^\s*match\s+vlan\s+(?P<id>\d+)\s+inner\s*$"
        )

        current_class_map_name = None
        active_class_map_data = {}

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

                active_class_map_data = parsed_dict["class_map"].setdefault(
                    current_class_map_name, {}
                )
                active_class_map_data["match_type"] = match_type
                continue

            if not current_class_map_name or not active_class_map_data:
                continue

            # Match 'vlan <id> inner'
            m_vlan_inner = p_match_vlan_id_inner.match(line)
            if m_vlan_inner:
                group = m_vlan_inner.groupdict()
                vlan_data = active_class_map_data.setdefault("vlan", {})
                vlan_data["id"] = int(group["id"])
                vlan_data["inner"] = True
                continue

            # Match 'vlan <id>'
            m_vlan = p_match_vlan_id.match(line)
            if m_vlan:
                group = m_vlan.groupdict()
                vlan_data = active_class_map_data.setdefault("vlan", {})
                vlan_data["id"] = int(group["id"])
                if "inner" not in vlan_data:
                    pass
                continue

            # Match 'access-group'
            m_ag = p_match_access_group.match(line)
            if m_ag:
                group = m_ag.groupdict()
                active_class_map_data["access_group"] = group["name"]
                continue

            # Match 'cos'
            m_cos = p_match_cos.match(line)
            if m_cos:
                group = m_cos.groupdict()
                active_class_map_data["cos"] = int(group["value"])
                continue

            # Match 'discard-class'
            m_dc = p_match_discard_class.match(line)
            if m_dc:
                group = m_dc.groupdict()
                active_class_map_data["discard_class"] = group["value"]
                continue

            # Match 'dscp' or 'ip dscp'
            m_dscp = p_match_dscp.match(line)
            if m_dscp:
                group = m_dscp.groupdict()
                value = group["value"]
                try:
                    active_class_map_data["dscp"] = int(value)
                except ValueError:
                    active_class_map_data["dscp"] = value
                continue

            # Match 'group-object [type] source'
            m_gos = p_match_group_object_source.match(line)
            if m_gos:
                group = m_gos.groupdict()
                group_object_data = active_class_map_data.setdefault("group_object", {})
                group_object_data["source"] = group["name"]
                continue

            # Match 'group-object [type] destination'
            m_god = p_match_group_object_destination.match(line)
            if m_god:
                group = m_god.groupdict()
                group_object_data = active_class_map_data.setdefault("group_object", {})
                group_object_data["destination"] = group["name"]
                continue

            # Match 'mpls experimental topmost'
            m_mpls = p_match_mpls_exp.match(line)
            if m_mpls:
                group = m_mpls.groupdict()
                active_class_map_data["mpls_experimental_topmost"] = int(group["value"])
                continue

            # Match 'precedence' or 'ip precedence'
            m_prec = p_match_precedence.match(line)
            if m_prec:
                group = m_prec.groupdict()
                value = group["value"]
                try:
                    active_class_map_data["precedence"] = int(value)
                except ValueError:
                    pass
                continue

            # Match 'qos-group'
            m_qos = p_match_qos_group.match(line)
            if m_qos:
                group = m_qos.groupdict()
                active_class_map_data["qos_group"] = int(group["value"])
                continue

            # Match 'service instance [type] <id>'
            m_si = p_match_service_instance.match(line)
            if m_si:
                group = m_si.groupdict()
                active_class_map_data["service_instance"] = int(group["id"])
                continue

            m_ip = p_match_ip.match(line)
            if m_ip:
                group = m_ip.groupdict()
                active_class_map_data["ip"] = group["value"]
                continue

        return parsed_dict
