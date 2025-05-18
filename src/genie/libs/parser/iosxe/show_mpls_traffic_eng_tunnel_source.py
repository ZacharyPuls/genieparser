import re

from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import Any, Optional, Schema


# ==============================================================================
# Schema for 'show mpls traffic-eng tunnels source-id [source_ip] [tunnel_id]'
# ==============================================================================
class ShowMplsTrafficEngTunnelsSourceIdSchema(MetaParser):
    """Schema for show mpls traffic-eng tunnels source-id [source_ip] [tunnel_id]"""

    schema = {
        Optional("p2p_tunnels"): {
            Any(): {  # Tunnel Name, e.g., WCHTNCS62_t12832
                Optional("signalled_status"): str,
                Optional("connection_status"): str,
                "lsps": {
                    Any(): {  # LSP identified by Tun_Instance
                        "in_label": {
                            "interface": str,
                            "label_id": str,
                        },
                        "prev_hop": str,
                        "out_label": {
                            "interface": str,
                            "label_id": str,
                        },
                        "next_hop": str,
                        "rsvp_signalling_info": {
                            "src": str,
                            "dst": str,
                            "tun_id": int,
                            "tun_instance": int,
                        },
                        "rsvp_path_info": {
                            "my_address": str,
                            "explicit_route": str,
                            "record_route": str,
                            "tspec": {
                                "ave_rate_kbits": int,
                                "burst_bytes": int,
                                "peak_rate_kbits": int,
                            },
                        },
                        "rsvp_resv_info": {
                            "record_route": str,
                            "fspec": {
                                "ave_rate_kbits": int,
                                "burst_bytes": int,
                                "peak_rate_kbits": int,
                            },
                        },
                    }
                },
            }
        },
        Optional("p2mp_tunnels"): {
            # Schema can be defined here if P2MP tunnel details are needed in the future
            # For now, it will be an empty dict if the section header is present but no data
        },
        Optional("p2mp_sub_lsps"): {
            # Schema can be defined here if P2MP sub-LSP details are needed
        },
    }


# ==============================================================================
# Parser for 'show mpls traffic-eng tunnels source-id [source_ip] [tunnel_id]'
# ==============================================================================
class ShowMplsTrafficEngTunnelsSourceId(ShowMplsTrafficEngTunnelsSourceIdSchema):
    """Parser for show mpls traffic-eng tunnels source-id [source_ip] [tunnel_id]"""

    # The actual CLI command can vary slightly based on exact NOS and parameters used.
    # This is a common representation.
    cli_command = "show mpls traffic-eng tunnels source-id {source_ip} {tunnel_id}"
    # If only one parameter (either source_ip or tunnel_id) is allowed, adjust accordingly
    # Or if both are optional for a wider "show mpls traffic-eng tunnels"
    # For the provided output, it seems like a specific tunnel is queried.

    def cli(self, source_ip=None, tunnel_id=None, output=None):
        if output is None:
            if source_ip and tunnel_id:
                output = self.device.execute(
                    self.cli_command.format(source_ip=source_ip, tunnel_id=tunnel_id)
                )

        # Initialize result dictionary
        ret_dict = {}

        # Regex patterns
        # LSP Tunnel WCHTNCS62_t12832 is signalled, connection is up
        p1_lsp_tunnel_header = re.compile(
            r"^LSP Tunnel\s+(?P<tunnel_name>\S+)\s+is\s+(?P<signalled_status>\S+),\s+connection\s+is\s+(?P<connection_status>.+)$"
        )

        #  InLabel  : TenGigabitEthernet0/0/26, explicit-null
        p2_in_label = re.compile(
            r"^\s*InLabel\s*:\s*(?P<interface>[^,]+),\s*(?P<label_id>.+)$"
        )

        #  Prev Hop : 10.9.4.165
        p3_prev_hop = re.compile(r"^\s*Prev Hop\s*:\s*(?P<prev_hop>.+)$")

        #  OutLabel :  -
        #  OutLabel : TenGigabitEthernet0/0/27, 25033
        p4_out_label = re.compile(
            r"^\s*OutLabel\s*:\s*(?P<interface>[^,]+),\s*(?P<label_id>.+)$"
        )

        # Next Hop : 10.9.4.161
        p4_next_hop = re.compile(r"^\s*Next\s*Hop\s*:\s*(?P<next_hop>.+)$")

        #       Src 10.9.1.188, Dst 10.9.1.27, Tun_Id 12832, Tun_Instance 34
        p5_rsvp_signal = re.compile(
            r"^\s*Src\s+(?P<src>\S+),\s+Dst\s+(?P<dst>\S+),\s+Tun_Id\s+(?P<tun_id>\d+),\s+Tun_Instance\s+(?P<tun_instance>\d+)$"
        )

        #      My Address: 10.9.1.27
        p6_my_address = re.compile(r"^\s*My Address:\s*(?P<my_address>\S+)$")

        #      Explicit Route:  NONE
        p7_explicit_route = re.compile(r"^\s*Explicit Route:\s*(?P<explicit_route>.+)$")

        #      Record   Route:   NONE
        p8_record_route = re.compile(r"^\s*Record\s+Route:\s*(?P<record_route>.+)$")

        #      Tspec: ave rate=0 kbits, burst=1000 bytes, peak rate=0 kbits
        p9_tspec = re.compile(
            r"^\s*Tspec:\s*ave rate=(?P<ave_rate>\d+)\s*kbits,\s*burst=(?P<burst>\d+)\s*bytes,\s*peak rate=(?P<peak_rate>\d+)\s*kbits$"
        )

        #      Fspec: ave rate=0 kbits, burst=0 bytes, peak rate=0 kbits
        p10_fspec = re.compile(
            r"^\s*Fspec:\s*ave rate=(?P<ave_rate>\d+)\s*kbits,\s*burst=(?P<burst>\d+)\s*bytes,\s*peak rate=(?P<peak_rate>\d+)\s*kbits$"
        )

        current_tunnel_name = None
        current_lsp_dict = {}  # Holds data for the current LSP block being parsed
        active_section = None  # To track P2P, P2MP etc.
        # Flags to know which "Record Route" we are parsing
        in_rsvp_path_info = False
        in_rsvp_resv_info = False

        for line in output.splitlines():
            line = (
                line.rstrip()
            )  # Keep leading spaces for indented lines if needed by regex, but strip trailing.
            if not line.strip():  # Skip empty lines
                continue

            # Section Headers
            if line.startswith("P2P TUNNELS/LSPs:"):
                active_section = "p2p"
                ret_dict.setdefault("p2p_tunnels", {})
                continue
            elif line.startswith("P2MP TUNNELS:"):
                active_section = "p2mp"
                ret_dict.setdefault("p2mp_tunnels", {})
                continue
            elif line.startswith("P2MP SUB-LSPS:"):
                active_section = "p2mp_sub_lsps"
                ret_dict.setdefault("p2mp_sub_lsps", {})
                continue

            if active_section == "p2p":
                # LSP Tunnel Header
                m = p1_lsp_tunnel_header.match(line)
                if m:
                    group = m.groupdict()
                    current_tunnel_name = group["tunnel_name"]
                    # Initialize tunnel if not exists, store status
                    tunnel_entry = ret_dict["p2p_tunnels"].setdefault(
                        current_tunnel_name, {}
                    )
                    tunnel_entry["signalled_status"] = group["signalled_status"].rstrip(
                        ","
                    )  # Remove trailing comma if any
                    tunnel_entry["connection_status"] = group["connection_status"]
                    tunnel_entry.setdefault("lsps", {})
                    current_lsp_dict = {}  # Reset for new LSP details
                    in_rsvp_path_info = False  # Reset context for new LSP
                    in_rsvp_resv_info = False
                    continue

                if (
                    not current_tunnel_name
                ):  # Skip lines if not under a tunnel context yet
                    continue

                # InLabel
                m = p2_in_label.match(line)
                if m:
                    group = m.groupdict()
                    current_lsp_dict.setdefault("in_label", {}).update(
                        {
                            "interface": group["interface"].strip(),
                            "label_id": group["label_id"].strip(),
                        }
                    )
                    continue

                # Prev Hop
                m = p3_prev_hop.match(line)
                if m:
                    current_lsp_dict["prev_hop"] = m.groupdict()["prev_hop"]
                    continue

                # OutLabel
                m = p4_out_label.match(line)
                if m:
                    group = m.groupdict()
                    current_lsp_dict.setdefault("out_label", {}).update(
                        {
                            "interface": group["interface"].strip(),
                            "label_id": group["label_id"].strip(),
                        }
                    )
                    continue

                # Next Hop
                m = p4_next_hop.match(line)
                if m:
                    current_lsp_dict["next_hop"] = m.groupdict()["next_hop"]

                # RSVP Signalling Info Header
                if "RSVP Signalling Info:" in line:
                    # This line is just a header, next line has data
                    continue

                # RSVP Signalling Info Data
                m = p5_rsvp_signal.match(line)
                if m:
                    group = m.groupdict()
                    rsvp_sig_info = current_lsp_dict.setdefault(
                        "rsvp_signalling_info", {}
                    )
                    rsvp_sig_info["src"] = group["src"]
                    rsvp_sig_info["dst"] = group["dst"]
                    rsvp_sig_info["tun_id"] = int(group["tun_id"])
                    rsvp_sig_info["tun_instance"] = int(group["tun_instance"])
                    # This is where we slot the current_lsp_dict into the main structure
                    # using tun_instance as the key for this specific LSP
                    ret_dict["p2p_tunnels"][current_tunnel_name]["lsps"][
                        rsvp_sig_info["tun_instance"]
                    ] = current_lsp_dict
                    continue

                # RSVP Path Info Header
                if "RSVP Path Info:" in line:
                    in_rsvp_path_info = True
                    in_rsvp_resv_info = False
                    current_lsp_dict.setdefault("rsvp_path_info", {})
                    continue

                # My Address (within Path Info)
                m = p6_my_address.match(line)
                if m and in_rsvp_path_info:
                    current_lsp_dict["rsvp_path_info"]["my_address"] = m.groupdict()[
                        "my_address"
                    ]
                    continue

                # Explicit Route (within Path Info)
                m = p7_explicit_route.match(line)
                if m and in_rsvp_path_info:
                    current_lsp_dict["rsvp_path_info"][
                        "explicit_route"
                    ] = m.groupdict()["explicit_route"].strip()
                    continue

                # Record Route (can be in Path Info or Resv Info)
                m = p8_record_route.match(line)
                if m:
                    rr_value = m.groupdict()["record_route"].strip()
                    if in_rsvp_path_info:
                        current_lsp_dict["rsvp_path_info"]["record_route"] = rr_value
                    elif in_rsvp_resv_info:
                        current_lsp_dict["rsvp_resv_info"]["record_route"] = rr_value
                    continue

                # Tspec (within Path Info)
                m = p9_tspec.match(line)
                if m and in_rsvp_path_info:
                    group = m.groupdict()
                    tspec = current_lsp_dict["rsvp_path_info"].setdefault("tspec", {})
                    tspec["ave_rate_kbits"] = int(group["ave_rate"])
                    tspec["burst_bytes"] = int(group["burst"])
                    tspec["peak_rate_kbits"] = int(group["peak_rate"])
                    continue

                # RSVP Resv Info Header
                if "RSVP Resv Info:" in line:
                    in_rsvp_resv_info = True
                    in_rsvp_path_info = False
                    current_lsp_dict.setdefault("rsvp_resv_info", {})
                    continue

                # Fspec (within Resv Info)
                m = p10_fspec.match(line)
                if m and in_rsvp_resv_info:
                    group = m.groupdict()
                    fspec = current_lsp_dict["rsvp_resv_info"].setdefault("fspec", {})
                    fspec["ave_rate_kbits"] = int(group["ave_rate"])
                    fspec["burst_bytes"] = int(group["burst"])
                    fspec["peak_rate_kbits"] = int(group["peak_rate"])
                    # This is typically the last item for an LSP entry.
                    # The current_lsp_dict is already linked via tun_instance.
                    continue

            # Add elif active_section == "p2mp": for P2MP specific parsing if needed
            # Add elif active_section == "p2mp_sub_lsps": for P2MP Sub-LSP specific parsing

        return ret_dict
