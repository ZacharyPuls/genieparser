import re

from genie.metaparser import MetaParser  # type: ignore
from genie.metaparser.util.schemaengine import Any, Optional, Schema  # type: ignore


# ======================================================
# Schema for 'show mpls traffic-eng tunnels {tunnel_id}'
# ======================================================
class ShowMplsTrafficEngTunnelsTunnelidSchema(MetaParser):
    """Schema for
    show mpls traffic-eng tunnels {tunnel_id}
    """

    schema = {
        "tunnel": {
            Any(): {
                "destination": str,
                "ifhandle": str,
                "signalled_name": str,
                "status": {
                    "admin": str,
                    "oper": str,
                    "path": str,
                    "signalling": str,
                    Optional("path_option"): {
                        Optional(Any()): {
                            Optional("type"): str,
                            Optional("path_weight"): int,
                            Optional("accumulative_metrics"): {
                                Optional("te"): int,
                                Optional("igp"): int,
                                Optional("path"): int,
                            },
                        }
                    },
                    Optional("last_pcalc_error"): {
                        "time": str,
                        "info": str,
                        "reverselink": str,
                    },
                    "g_pid": str,
                    "bandwidth_requested": int,
                    "bandwidth_requested_unit": str,
                    "creation_time": str,
                },
                "config_parameters": {
                    "bandwidth": int,
                    "bandwidth_unit": str,
                    "priority": int,
                    "affinity": str,
                    "metric_type": str,
                    "path_selection": {"tiebreaker": str},
                    "hop_limit": str,
                    "cost_limit": str,
                    "delay_limit": str,
                    "delay_measurement": str,
                    "path_invalidation_timeout": int,
                    "path_invalidation_timeout_unit": str,
                    "action": str,
                    "autoroute": str,
                    "lockdown": str,
                    "policy_class": str,
                    "forward_class": int,
                    "forward_class_state": str,
                    "forwarding_adjacency": str,
                    "autoroute_destinations": int,
                    "loadshare": int,
                    "loadshare_state": str,
                    "auto_bw": str,
                    "auto_capacity": str,
                    "fast_reroute": str,
                    "protection_desired": str,
                    "path_protection": str,
                    "bfd_fast_detection": str,
                    "reoptimization_after_affinity_failure": str,
                    "soft_preemption": str,
                },
                "history": {
                    "tunnel_up_time": str,
                    "current_lsp": {"uptime": str},
                    "reopt_lsp": {
                        "lsp_failure": {"lsp": str, "lsp_status": str, "date_time": str}
                    },
                    "prior_lsp": {
                        "id": int,
                        "path_option": int,
                        "removal_trigger": str,
                    },
                },
                "path_info": {
                    Any(): {"node_hop_count": int, "hop": {Any(): {"ip_address": str}}}
                },
                "displayed": {
                    "heads_displayed": int,
                    "total_heads": int,
                    "midpoints_displayed": int,
                    "total_midpoints": int,
                    "tails_displayed": int,
                    "total_tails": int,
                    "status": {
                        "up": int,
                        "down": int,
                        "recovering": int,
                        "recovered_heads": int,
                    },
                },
            }
        }
    }


class ShowMplsTrafficEngTunnelsTunnelid(ShowMplsTrafficEngTunnelsTunnelidSchema):
    """
    Parser for show mpls traffic-eng tunnels {tunnel_id}
    """

    cli_command = ["show mpls traffic-eng tunnels {tunnel_id}"]

    def cli(self, output=None, tunnel_id=None):
        if output is None:
            out = self.device.execute(self.cli_command[0].format(tunnel_id=tunnel_id))
        else:
            out = output

        # initial return dictionary
        ret_dict = {}

        path_basis_dict = {}

        # Name: tunnel-te50000  Destination: 109.109.109.109  Ifhandle:0x20e0
        p1 = re.compile(
            r"^(Tunnel\s+)?Name:\s+(?P<tunnel>\S+)\s+Destination:\s+(?P<destination>\S+)"
            r"\s+Ifhandle:(?P<ifhandle>\S+)$"
        )

        # Signalled-Name: 50000_F17-ASR9922_F109-ASR9001
        p2 = re.compile(r"^Signalled-Name:\s+(?P<signalled_name>\S+)$")

        # Admin:    up Oper:   up   Path:  valid   Signalling: connected
        p3 = re.compile(
            r"^Admin:\s+(?P<admin>\S+)\s+Oper:\s+(?P<oper>\S+)\s+Path:\s+(?P<path>\S+)"
            r"\s+Signalling:\s+(?P<signalling>\S+)$"
        )

        # path option 10,  type explicit 50000-EPath_10 (Basis for Setup, path weight 160)
        # path option 10,  type explicit CLWRNCS61_TYRONCS62_MPLS-T_8241_WORK (Basis for Setup, path weight 5)
        # path option 20,  type explicit CLWRNCS61_TYRONCS62_MPLS-T_8241_PROTECT (Basis for Standby, path weight 17)
        p4 = re.compile(
            r"^path +option\s+(?P<path_option>\d+),\s+type\s+(?P<type>\S+)"
            r"\s+?(?P<path_name>\S+)?\s+\([Bb]asis\s+for\s+(?P<path_basis>\S+),\s+path weight\s+(?P<path_weight>\d+)\)$"
        )

        # path option 20,  type explicit 50000-EPath_20
        # path option 100,  type dynamic
        p4_1 = re.compile(
            r"^path +option\s+(?P<path_option>\d+),\s+type\s+(?P<type>\S+)"
            r"[\s+]?(?P<path_name>\S+)?$"
        )

        # Accumulative metrics: TE 160 IGP 160 Delay 600000
        p5 = re.compile(
            r"^Accumulative +metrics:\s+TE\s+(?P<te>\d+)\s+IGP\s+"
            r"(?P<igp>\d+)\s+Delay\s+(?P<path>\d+)$"
        )

        # Last PCALC Error: Tue Apr 27 16:21:21 2021
        p6 = re.compile(r"^Last PCALC Error:(?P<last_pcalc_error>.+)$")

        # Info: No path to destination, 109.109.109.109 (reverselink)
        p7 = re.compile(
            r"^Info:\s+(?P<info>.*)\, (?P<reverselink>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+$"
        )

        # G-PID: 0x0800 (derived from egress interface properties)
        p8 = re.compile(r"^G-PID:\s+(?P<g_pid>\S+).+$")

        # Bandwidth Requested: 0 kbps  CT0
        p9 = re.compile(
            r"^Bandwidth Requested:\s+(?P<bandwidth_requested>\S+)\s+"
            r"(?P<bandwidth_requested_unit>\S+).+$"
        )

        # Creation Time: Tue Apr 27 16:21:14 2021 (01:36:30 ago)
        p10 = re.compile(r"^Creation Time:\s+(?P<creation_time>.+)$")

        # Bandwidth:        0 kbps (CT0) Priority:  3  3 Affinity: 0x0/0xffff
        p11 = re.compile(
            r"^Bandwidth:\s+(?P<bandwidth>\d+)\s+(?P<bandwidth_unit>\S+)"
            r".*Priority:\s+(?P<priority>\d+).*(Affinity:\s+(?P<affinity>\S+))?$"
        )

        # Metric Type: IGP (interface)
        p12 = re.compile(r"^Metric Type:\s+(?P<metric_type>.+)$")

        # Tiebreaker: Min-fill (default)
        p13 = re.compile(r"^Tiebreaker:\s+(?P<tiebreaker>.+)$")

        # Hop-limit: disabled
        p14 = re.compile(r"^Hop-limit:\s+(?P<hop_limit>.+)$")

        # Cost-limit: disabled
        p15 = re.compile(r"^Cost-limit:\s+(?P<cost_limit>.+)$")

        # Delay-limit: disabled
        p16 = re.compile(r"^Delay-limit:\s+(?P<delay_limit>.+)$")

        # Delay-measurement: disabled
        p17 = re.compile(r"^Delay-measurement:\s+(?P<delay_measurement>.+)$")

        # Path-invalidation timeout: 10000 msec (default), Action: Tear (default)
        p18 = re.compile(
            r"^Path-invalidation timeout:\s+(?P<timeout>\d+)\s+(?P<timeout_unit>\S+)"
            r".*,\s+Action:\s+(?P<action>\S+).+$"
        )

        # AutoRoute:  enabled  LockDown: disabled   Policy class: not set
        p19 = re.compile(
            r"^AutoRoute:\s+(?P<autoroute>\S+)\s+LockDown:\s+(?P<lockdown>.+)\s+"
            r"Policy class:\s+(?P<policy_class>.+)$"
        )

        # Forward class: 0 (not enabled)
        p20 = re.compile(
            r"^Forward class:\s+(?P<forward_class>\S+)\s+\((?P<forward_class_state>.+)?\)$"
        )

        # Forwarding-Adjacency: disabled
        p21 = re.compile(r"^Forwarding-Adjacency:\s+(?P<forwarding_adjacency>.+)$")

        # Autoroute Destinations: 0
        p22 = re.compile(r"^Autoroute Destinations:\s+(?P<autoroute_destinations>.+)$")

        # Loadshare:          0 equal loadshares
        p23 = re.compile(r"^Loadshare:\s+(?P<loadshare>\d+)\s+(?P<loadshare_state>.+)$")

        # Auto-bw: disabled
        p24 = re.compile(r"^Auto-bw:\s+(?P<auto_bw>.+)$")

        # Auto-Capacity: Disabled:
        p25 = re.compile(r"^Auto-Capacity:\s+(?P<auto_capacity>\w+)\:?$")

        # Fast Reroute: Enabled, Protection Desired: Any
        p26 = re.compile(
            r"^Fast Reroute:\s+(?P<fast_reroute>\S+), Protection Desired:"
            r"\s+(?P<protection_desired>.+)$"
        )

        # Path Protection: Not Enabled
        p27 = re.compile(r"^Path Protection:\s+(?P<path_protection>.+)$")

        # BFD Fast Detection: Disabled
        p28 = re.compile(r"^BFD Fast Detection:\s+(?P<bfd_fast_detection>.+)$")

        # Reoptimization after affinity failure: Enabled
        p29 = re.compile(
            r"^Reoptimization after affinity failure:\s+(?P<reoptimization>.+)$"
        )

        # Soft Preemption: Disabled
        p30 = re.compile(r"^Soft Preemption:\s+(?P<soft_preemption>.+)$")

        # Tunnel has been up for: 01:36:23 (since Tue Apr 27 16:21:21 JST 2021)
        p31 = re.compile(r"^Tunnel has been up for:\s+(?P<tunnel_up_time>.+)$")

        # Uptime: 00:26:32 (since Tue Apr 27 17:31:12 JST 2021)
        p32 = re.compile(r"^Uptime:\s+(?P<uptime>.+)$")

        # LSP not signalled, identical to the [CURRENT] LSP
        p33 = re.compile(r"^LSP\s+(?P<lsp>.+),\s+(?P<lsp_status>.+)$")

        # Date/Time: Tue Apr 27 16:26:11 JST 2021 [01:31:33 ago]
        p34 = re.compile(r"^Date/Time:\s+(?P<date_time>.+)$")

        # ID: 5 Path Option: 20
        p35 = re.compile(r"^ID:\s+(?P<id>\d+)\s+Path Option:\s+(?P<path_option>\d+)$")

        # Removal Trigger: reoptimization completed
        p36 = re.compile(r"^Removal Trigger:\s+(?P<removal_trigger>.+)$")

        # Path info (OSPF mpls1 area 0):
        # Standby LSP Path info (OSPF 13329 area 0), Oper State: Up :
        p37 = re.compile(
            r"^(?P<standby_path>\S+)?(.+)?Path info \((?P<path_info>.+)\).*:$"
        )

        # Node hop count: 2
        p38 = re.compile(r"^Node hop count:\s+(?P<node_hop_count>.+)$")

        # Hop0: 20.50.0.1
        # Hop1: 21.50.0.2
        # Hop2: 109.109.109.109
        p39 = re.compile(
            r"^Hop(?P<hop>\d+):\s+(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        )

        # Displayed 1 (of 9) heads, 0 (of 10) midpoints, 0 (of 6) tails
        p40 = re.compile(
            r"^Displayed\s+(?P<heads_displayed>\d+)\s+\(of\s+(?P<total_heads>\d+)\)"
            r"\s+heads,\s+(?P<midpoints_displayed>\d+)\s+\(of\s+(?P<total_midpoints>\d+)"
            r"\)\s+midpoints,\s+(?P<tails_displayed>\d+)\s+\(of\s+(?P<total_tails>\d+)\)\s+tails$"
        )

        # Displayed 1 up, 0 down, 0 recovering, 0 recovered heads
        p41 = re.compile(
            r"^Displayed\s+(?P<up>\d+)\s+up,\s+(?P<down>\d+)\s+down,"
            r"\s+(?P<recovering>\d+)\s+recovering,\s+(?P<recovered_heads>\d+).+$"
        )

        for line in out.splitlines():
            line = line.strip()

            # Name: tunnel-te50000  Destination: 109.109.109.109  Ifhandle:0x20e0
            m = p1.match(line)
            if m:
                group = m.groupdict()
                tunnel_dict = ret_dict.setdefault("tunnel", {}).setdefault(
                    group["tunnel"], {}
                )
                tunnel_dict.update(
                    {"destination": group["destination"], "ifhandle": group["ifhandle"]}
                )
                continue

            # Signalled-Name: 50000_F17-ASR9922_F109-ASR9001
            m = p2.match(line)
            if m:
                group = m.groupdict()
                tunnel_dict.update({"signalled_name": group["signalled_name"]})
                continue

            # Admin:    up Oper:   up   Path:  valid   Signalling: connected
            m = p3.match(line)
            if m:
                group = m.groupdict()
                status_dict = tunnel_dict.setdefault("status", {})
                status_dict.update({k: v for k, v in group.items() if v is not None})
                continue

            # path option 10,  type explicit 50000-EPath_10 (Basis for Setup, path weight 160)
            # path option 20,  type explicit CLWRNCS61_TYRONCS62_MPLS-T_8241_PROTECT (Basis for Standby, path weight 17)
            m = p4.match(line)
            if m:
                group = m.groupdict()
                path_option = int(group["path_option"])
                path_option_dict = status_dict.setdefault("path_option", {}).setdefault(
                    path_option, {}
                )
                path_option_dict.update(
                    {"type": group["type"], "path_weight": int(group["path_weight"])}
                )
                if "path_basis" in group:
                    path_basis_dict[group["path_basis"]] = path_option
                continue

            # path option 20,  type explicit 50000-EPath_20
            # path option 100,  type dynamic
            m = p4_1.match(line)
            if m:
                group = m.groupdict()
                path_option = int(group["path_option"])
                path_option_dict = status_dict.setdefault("path_option", {}).setdefault(
                    path_option, {}
                )
                path_option_dict.update({"type": group["type"]})
                continue

            # Accumulative metrics: TE 160 IGP 160 Delay 600000
            m = p5.match(line)
            if m:
                group = m.groupdict()
                accumulative_metrics_dict = path_option_dict.setdefault(
                    "accumulative_metrics", {}
                )
                accumulative_metrics_dict.update(
                    {k: int(v) for k, v in group.items() if v is not None}
                )
                continue

            # Last PCALC Error: Tue Apr 27 16:21:21 2021
            m = p6.match(line)
            if m:
                group = m.groupdict()
                last_pcalc_error_dict = status_dict.setdefault("last_pcalc_error", {})
                last_pcalc_error_dict.update({"time": group["last_pcalc_error"]})
                continue

            # Info: No path to destination, 109.109.109.109 (reverselink)
            m = p7.match(line)
            if m:
                group = m.groupdict()
                last_pcalc_error_dict.update(
                    {"info": group["info"], "reverselink": group["reverselink"]}
                )
                continue

            # G-PID: 0x0800 (derived from egress interface properties)
            m = p8.match(line)
            if m:
                group = m.groupdict()
                status_dict.update({"g_pid": group["g_pid"]})
                continue

            # Bandwidth Requested: 0 kbps  CT0
            m = p9.match(line)
            if m:
                group = m.groupdict()
                status_dict.update(
                    {
                        "bandwidth_requested": int(group["bandwidth_requested"]),
                        "bandwidth_requested_unit": group["bandwidth_requested_unit"],
                    }
                )
                continue

            # Creation Time: Tue Apr 27 16:21:14 2021 (01:36:30 ago)
            m = p10.match(line)
            if m:
                group = m.groupdict()
                status_dict.update({"creation_time": group["creation_time"]})
                continue

            # Bandwidth:        0 kbps (CT0) Priority:  3  3 Affinity: 0x0/0xffff
            m = p11.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict = tunnel_dict.setdefault("config_parameters", {})
                config_parameters_dict.update(
                    {
                        "bandwidth": int(group["bandwidth"]),
                        "bandwidth_unit": group["bandwidth_unit"],
                        "priority": int(group["priority"]),
                        "affinity": group["affinity"],
                    }
                )
                continue

            # Metric Type: IGP (interface)
            m = p12.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"metric_type": group["metric_type"]})
                continue

            # Tiebreaker: Min-fill (default)
            m = p13.match(line)
            if m:
                group = m.groupdict()
                path_selection = config_parameters_dict.setdefault("path_selection", {})
                path_selection.update({"tiebreaker": group["tiebreaker"]})
                continue

            # Hop-limit: disabled
            m = p14.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"hop_limit": group["hop_limit"]})
                continue

            # Cost-limit: disabled
            m = p15.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"cost_limit": group["cost_limit"]})
                continue

            # Delay-limit: disabled
            m = p16.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"delay_limit": group["delay_limit"]})
                continue

            # Delay-measurement: disabled
            m = p17.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"delay_measurement": group["delay_measurement"]}
                )
                continue

            # Path-invalidation timeout: 10000 msec (default), Action: Tear (default)
            m = p18.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {
                        "path_invalidation_timeout": int(group["timeout"]),
                        "path_invalidation_timeout_unit": group["timeout_unit"],
                        "action": group["action"],
                    }
                )
                continue

            # AutoRoute:  enabled  LockDown: disabled   Policy class: not set
            m = p19.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {k: v for k, v in group.items() if v is not None}
                )
                continue

            # Forward class: 0 (not enabled)
            m = p20.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {
                        "forward_class": int(group["forward_class"]),
                        "forward_class_state": group["forward_class_state"],
                    }
                )
                continue

            # Forwarding-Adjacency: disabled
            m = p21.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"forwarding_adjacency": group["forwarding_adjacency"]}
                )
                continue

            # Autoroute Destinations: 0
            m = p22.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"autoroute_destinations": int(group["autoroute_destinations"])}
                )
                continue

            # Loadshare:          0 equal loadshares
            m = p23.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {
                        "loadshare": int(group["loadshare"]),
                        "loadshare_state": group["loadshare_state"],
                    }
                )
                continue

            # Auto-bw: disabled
            m = p24.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"auto_bw": group["auto_bw"]})
                continue

            # Auto-Capacity: Disabled:
            m = p25.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update({"auto_capacity": group["auto_capacity"]})
                continue

            # Fast Reroute: Enabled, Protection Desired: Any
            m = p26.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {
                        "fast_reroute": group["fast_reroute"],
                        "protection_desired": group["protection_desired"],
                    }
                )
                continue

            # Path Protection: Not Enabled
            m = p27.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"path_protection": group["path_protection"]}
                )
                continue

            # BFD Fast Detection: Disabled
            m = p28.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"bfd_fast_detection": group["bfd_fast_detection"]}
                )
                continue

            # Reoptimization after affinity failure: Enabled
            m = p29.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"reoptimization_after_affinity_failure": group["reoptimization"]}
                )
                continue

            # Soft Preemption: Disabled
            m = p30.match(line)
            if m:
                group = m.groupdict()
                config_parameters_dict.update(
                    {"soft_preemption": group["soft_preemption"]}
                )
                continue

            # Tunnel has been up for: 01:36:23 (since Tue Apr 27 16:21:21 JST 2021)
            m = p31.match(line)
            if m:
                group = m.groupdict()
                history_dict = tunnel_dict.setdefault("history", {})
                history_dict.update({"tunnel_up_time": group["tunnel_up_time"]})
                continue

            # Uptime: 00:26:32 (since Tue Apr 27 17:31:12 JST 2021)
            m = p32.match(line)
            if m:
                group = m.groupdict()
                current_lsp_dict = history_dict.setdefault("current_lsp", {})
                current_lsp_dict.update({"uptime": group["uptime"]})
                continue

            # LSP not signalled, identical to the [CURRENT] LSP
            m = p33.match(line)
            if m:
                group = m.groupdict()
                history_dict = tunnel_dict.setdefault("history", {})
                reopt_lsp_dict = history_dict.setdefault("reopt_lsp", {}).setdefault(
                    "lsp_failure", {}
                )
                reopt_lsp_dict.update(
                    {"lsp": group["lsp"], "lsp_status": group["lsp_status"]}
                )
                continue

            # Date/Time: Tue Apr 27 16:26:11 JST 2021 [01:31:33 ago]
            m = p34.match(line)
            if m:
                group = m.groupdict()
                reopt_lsp_dict.update({"date_time": group["date_time"]})
                continue

            # ID: 5 Path Option: 20
            m = p35.match(line)
            if m:
                group = m.groupdict()
                prior_lsp_dict = history_dict.setdefault("prior_lsp", {})
                prior_lsp_dict.update(
                    {"id": int(group["id"]), "path_option": int(group["path_option"])}
                )
                continue

            # Removal Trigger: reoptimization completed
            m = p36.match(line)
            if m:
                group = m.groupdict()
                prior_lsp_dict.update({"removal_trigger": group["removal_trigger"]})
                continue

            # Path info (OSPF mpls1 area 0):
            # Standby LSP Path info (OSPF 13329 area 0), Oper State: Up :
            m = p37.match(line)
            if m:
                group = m.groupdict()
                if path_basis_dict and group["standby_path"]:
                    path_info_temp_dict = tunnel_dict.setdefault(
                        "path_info", {}
                    ).setdefault(path_basis_dict[group["standby_path"]], {})
                elif path_basis_dict and not group["standby_path"]:
                    path_info_temp_dict = tunnel_dict.setdefault(
                        "path_info", {}
                    ).setdefault(path_basis_dict["Setup"], {})
                else:
                    path_info_temp_dict = tunnel_dict.setdefault(
                        "path_info", {}
                    ).setdefault(group["path_info"], {})
                continue

            # Node hop count: 2
            m = p38.match(line)
            if m:
                group = m.groupdict()
                path_info_temp_dict.update(
                    {"node_hop_count": int(group["node_hop_count"])}
                )
                continue

            # Hop0: 20.50.0.1
            # Hop1: 21.50.0.2
            # Hop2: 109.109.109.109
            m = p39.match(line)
            if m:
                group = m.groupdict()
                hop_dict = path_info_temp_dict.setdefault("hop", {}).setdefault(
                    int(group["hop"]), {}
                )
                hop_dict.update({"ip_address": group["ip_address"]})
                continue

            # Displayed 1 (of 9) heads, 0 (of 10) midpoints, 0 (of 6) tails
            m = p40.match(line)
            if m:
                group = m.groupdict()
                displayed_dict = tunnel_dict.setdefault("displayed", {})
                displayed_dict.update(
                    {k: int(v) for k, v in group.items() if v is not None}
                )
                continue

            # Displayed 1 up, 0 down, 0 recovering, 0 recovered heads
            m = p41.match(line)
            if m:
                group = m.groupdict()
                displayed_status_dict = displayed_dict.setdefault("status", {})
                displayed_status_dict.update(
                    {k: int(v) for k, v in group.items() if v is not None}
                )
                continue

        return ret_dict
