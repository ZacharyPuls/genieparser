import re

from genie.metaparser import MetaParser  # type: ignore
from genie.metaparser.util.schemaengine import Any, Optional, Or, Schema  # type: ignore


# ======================================================
# Schema for 'show qos interface {interface} {direction}'
# ======================================================
class ShowQosInterfaceSchema(MetaParser):
    """Schema for show qos interface {interface} {direction}"""

    schema = {
        Any(): {
            "interface_name": str,
            "direction": Or("input", "output"),
            "ifh": str,
            "npu_id": int,
            "total_classes": int,
            "interface_bandwidth": {
                "value": int,
                "unit": str,
            },
            "policy_name": str,
            "spi_id": str,
            "accounting_type": {
                "type": str,
                "description": str,
            },
            "classes": {
                Any(): {
                    "level": int,
                    "new_qos_group": int,
                    "new_traffic_class": int,
                    Optional("policer"): {
                        "configured": bool,
                        Optional("bucket_id"): str,
                        Optional("stats_handle"): str,
                        Optional("committed_rate"): {
                            "value": int,
                            "unit": str,
                            Optional("configured_value"): int,
                            Optional("configured_unit"): str,
                        },
                        Optional("peak_rate"): {
                            "value": int,
                            "unit": str,
                            Optional("configured_value"): int,
                            Optional("configured_unit"): str,
                        },
                        Optional("conform_burst"): {
                            "value": int,
                            "unit": str,
                            Optional("configured_value"): int,
                            Optional("configured_unit"): str,
                        },
                        Optional("exceed_burst"): {
                            "value": int,
                            "unit": str,
                            Optional("configured_value"): Or(
                                int, str
                            ),  # Can be 'default'
                            Optional("configured_unit"): str,
                        },
                    },
                }
            },
        }
    }


# ======================================================
# Parser for 'show qos interface {interface} {direction}'
# ======================================================
class ShowQosInterface(ShowQosInterfaceSchema):
    """Parser for show qos interface {interface} {direction}"""

    cli_command = "show qos interface {interface} {direction}"

    def cli(self, interface, direction, output=None):
        if output is None:
            output = self.device.execute(
                self.cli_command.format(interface=interface, direction=direction)
            )

        # --- Regular Expressions ---
        # Interface GigabitEthernet0/0/0/0.999 ifh 0x3c008062 -- input policy
        p_interface = re.compile(
            r"^Interface\s+(?P<intf>\S+)\s+ifh\s+(?P<ifh>\S+)\s+--\s+(?P<dir>input|output)\s+policy$"
        )
        # NPU Id: 0
        p_npu = re.compile(r"^NPU\s+Id:\s+(?P<npu_id>\d+)$")
        # Total number of classes: 2
        p_total_classes = re.compile(
            r"^Total\s+number\s+of\s+classes:\s+(?P<total_classes>\d+)$"
        )
        # Interface Bandwidth: 1000000 kbps
        p_intf_bw = re.compile(
            r"^Interface\s+Bandwidth:\s+(?P<bw_val>\d+)\s+(?P<bw_unit>\w+)$"
        )
        # Policy Name: 05VPLS3159KFN-INGRESS
        p_policy = re.compile(r"^Policy\s+Name:\s+(?P<policy_name>\S+)$")
        # SPI Id: 0x0
        p_spi = re.compile(r"^SPI\s+Id:\s+(?P<spi_id>\S+)$")
        # Accounting Type: Layer2 (Include Layer 2 encapsulation and above)
        p_accounting = re.compile(
            r"^Accounting\s+Type:\s+(?P<acc_type>\S+)\s+\((?P<acc_desc>.*)\)$"
        )

        # Level1 Class = CLASS-SERVICE-OAM-INGRESS
        p_class = re.compile(r"^Level(?P<level>\d+)\s+Class\s+=\s+(?P<class_name>\S+)$")
        # New qos group = 1
        p_qos_group = re.compile(r"^New\s+qos\s+group\s+=\s+(?P<qos_group>\d+)$")
        # New traffic class = 1
        p_traffic_class = re.compile(
            r"^New\s+traffic\s+class\s+=\s+(?P<traffic_class>\d+)$"
        )

        # Policer not configured for this class
        p_policer_not_conf = re.compile(
            r"^Policer\s+not\s+configured\s+for\s+this\s+class$"
        )
        # Default Policer Bucket ID = 0x79
        # Policer Bucket ID = 0x78
        p_policer_bucket = re.compile(
            r"^(?:Default\s+)?Policer\s+Bucket\s+ID\s+=\s+(?P<bucket_id>\S+)$"
        )
        # Default Policer Stats Handle = 0x0
        # Policer Stats Handle = 0x0
        p_policer_stats = re.compile(
            r"^(?:Default\s+)?Policer\s+Stats\s+Handle\s+=\s+(?P<stats_handle>\S+)$"
        )
        # Policer committed rate = 1978 kbps (2 mbits/sec)
        p_policer_rate_burst = re.compile(
            r"^Policer\s+(?P<type>committed\s+rate|peak\s+rate|conform\s+burst|exceed\s+burst)\s+"
            r"=\s+(?P<value>\d+)\s+(?P<unit>\w+)"
            r"(?:\s+\((?P<conf_value>\d+|default)\s+(?P<conf_unit>\S+)\))?$"
        )

        # --- Parsing Logic ---
        ret_dict = {}
        current_class_name = None
        interface_dict = None

        for line in output.splitlines():
            line = line.strip()

            # Interface Line
            m = p_interface.match(line)
            if m:
                group = m.groupdict()
                intf_name = group["intf"]
                # Check if interface name matches the requested one
                if intf_name != interface:
                    # This might happen if show command defaults or has ambiguity
                    # For robustness, we'll continue parsing but use the name from output
                    pass  # Or raise an error/warning if strict matching is needed
                if intf_name not in ret_dict:
                    ret_dict[intf_name] = {}
                interface_dict = ret_dict[intf_name]
                interface_dict["interface_name"] = intf_name
                interface_dict["direction"] = group["dir"].lower()
                interface_dict["ifh"] = group["ifh"]
                interface_dict["classes"] = {}  # Initialize classes dict
                continue

            if interface_dict is None:  # Skip lines until interface line is found
                continue

            # NPU ID
            m = p_npu.match(line)
            if m:
                interface_dict["npu_id"] = int(m.groupdict()["npu_id"])
                continue

            # Total Classes
            m = p_total_classes.match(line)
            if m:
                interface_dict["total_classes"] = int(m.groupdict()["total_classes"])
                continue

            # Interface Bandwidth
            m = p_intf_bw.match(line)
            if m:
                group = m.groupdict()
                interface_dict["interface_bandwidth"] = {
                    "value": int(group["bw_val"]),
                    "unit": group["bw_unit"],
                }
                continue

            # Policy Name
            m = p_policy.match(line)
            if m:
                interface_dict["policy_name"] = m.groupdict()["policy_name"]
                continue

            # SPI ID
            m = p_spi.match(line)
            if m:
                interface_dict["spi_id"] = m.groupdict()["spi_id"]
                continue

            # Accounting Type
            m = p_accounting.match(line)
            if m:
                group = m.groupdict()
                interface_dict["accounting_type"] = {
                    "type": group["acc_type"],
                    "description": group["acc_desc"],
                }
                continue

            # Class Definition Start
            m = p_class.match(line)
            if m:
                group = m.groupdict()
                current_class_name = group["class_name"]
                interface_dict["classes"][current_class_name] = {
                    "level": int(group["level"])
                }
                continue

            # --- Inside a Class Context ---
            if current_class_name:
                class_dict = interface_dict["classes"][current_class_name]

                # New QoS Group
                m = p_qos_group.match(line)
                if m:
                    class_dict["new_qos_group"] = int(m.groupdict()["qos_group"])
                    continue

                # New Traffic Class
                m = p_traffic_class.match(line)
                if m:
                    class_dict["new_traffic_class"] = int(
                        m.groupdict()["traffic_class"]
                    )
                    continue

                # Policer Not Configured
                m = p_policer_not_conf.match(line)
                if m:
                    if "policer" not in class_dict:
                        class_dict["policer"] = {}
                    class_dict["policer"]["configured"] = False
                    continue

                # Policer Bucket ID
                m = p_policer_bucket.match(line)
                if m:
                    if "policer" not in class_dict:
                        class_dict["policer"] = {"configured": True}
                    class_dict["policer"]["bucket_id"] = m.groupdict()["bucket_id"]
                    continue

                # Policer Stats Handle
                m = p_policer_stats.match(line)
                if m:
                    if "policer" not in class_dict:
                        class_dict["policer"] = {"configured": True}
                    class_dict["policer"]["stats_handle"] = m.groupdict()[
                        "stats_handle"
                    ]
                    continue

                # Policer Rate/Burst
                m = p_policer_rate_burst.match(line)
                if m:
                    if "policer" not in class_dict:
                        class_dict["policer"] = {"configured": True}
                    policer_dict = class_dict["policer"]

                    group = m.groupdict()
                    rate_burst_type = group["type"].replace(
                        " ", "_"
                    )  # e.g., "committed_rate"
                    policer_dict[rate_burst_type] = {
                        "value": int(group["value"]),
                        "unit": group["unit"],
                    }
                    if group["conf_value"]:
                        conf_val = group["conf_value"]
                        # Handle 'default' case for exceed burst
                        policer_dict[rate_burst_type]["configured_value"] = (
                            int(conf_val) if conf_val.isdigit() else conf_val
                        )
                        policer_dict[rate_burst_type]["configured_unit"] = group[
                            "conf_unit"
                        ]
                    continue

        return ret_dict
