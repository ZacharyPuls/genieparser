import collections
import re

import xmltodict

# import parser utils
from genie.libs.parser.utils.common import Common

# Metaparser
from genie.metaparser import MetaParser
from genie.metaparser.util.schemaengine import (
    And,
    Any,
    Default,
    Optional,
    Or,
    Schema,
    Use,
)
from netaddr import IPAddress, IPNetwork


class ShowPolicyMapTypeSchema(MetaParser):
    """Schema for :
    * 'show policy-map interface {interface}',
    * 'show policy-map interface {interface} service instance {service_instance}',
    * 'show policy-map interface {interface} service instance {service_instance} input',
    * 'show policy-map interface {interface} service instance {service_instance} output',
    """

    schema = {
        Any(): {
            Optional("service_group"): int,
            Optional("service_policy"): {
                Any(): {
                    Optional("policy_name"): {
                        Any(): {
                            Optional("class_map"): {
                                Any(): {
                                    "match_evaluation": str,
                                    "match": list,
                                    Optional("packets"): int,
                                    Optional("packet_output"): int,
                                    Optional("packet_drop"): int,
                                    Optional("tail_random_drops"): int,
                                    Optional("other_drops"): int,
                                    Optional("bytes"): int,
                                    Optional("queueing"): bool,
                                    Optional("queue_limit_packets"): str,
                                    Optional("queue_size"): int,
                                    Optional("queue_limit"): int,
                                    Optional("queue_limit_bytes"): int,
                                    Optional("queue_limit_us"): int,
                                    Optional("queue_depth"): int,
                                    Optional("total_drops"): int,
                                    Optional("no_buffer_drops"): int,
                                    Optional("pkts_output"): int,
                                    Optional("bytes_output"): int,
                                    Optional("pkts_matched"): int,
                                    Optional("bytes_matched"): int,
                                    Optional("pkts_queued"): int,
                                    Optional("bytes_queued"): int,
                                    Optional("shape_type"): str,
                                    Optional("shape_cir_bps"): int,
                                    Optional("shape_bc_bps"): int,
                                    Optional("shape_be_bps"): int,
                                    Optional("target_shape_rate"): int,
                                    Optional("output_queue"): str,
                                    Optional("bandwidth_percent"): int,
                                    Optional("bandwidth_kbps"): int,
                                    Optional("bandwidth"): str,
                                    Optional("bandwidth_remaining_ratio"): int,
                                    Optional("bandwidth_remaining_percent"): int,
                                    Optional("fair_queue_limit_per_flow"): int,
                                    Optional("bandwidth_max_threshold_packets"): int,
                                    Optional("priority_level"): int,
                                    Optional("overhead_accounting"): str,
                                    Optional("random_detect"): {
                                        Optional("exp_weight_constant"): str,
                                        Optional("exponential_weight"): str,
                                        Optional("mean_queue_depth"): int,
                                        Optional("class"): {
                                            Any(): {
                                                "transmitted_packets": str,
                                                "transmitted_bytes": str,
                                                "random_drop_packets": str,
                                                "random_drop_bytes": str,
                                                "tail_drop_packets": str,
                                                "tail_drop_bytes": str,
                                                "minimum_thresh": str,
                                                "maximum_thresh": str,
                                                "mark_prob": str,
                                                Optional("ecn_mark"): str,
                                            },
                                        },
                                    },
                                    Optional("priority"): {
                                        Optional("percent"): int,
                                        Optional("kbps"): int,
                                        Optional("burst_bytes"): int,
                                        Optional("exceed_drops"): int,
                                        Optional("type"): str,
                                    },
                                    Optional("rate"): {
                                        Optional("interval"): int,
                                        Optional("offered_rate_bps"): int,
                                        Optional("drop_rate_bps"): int,
                                    },
                                    Optional("policy"): {
                                        Any(): {
                                            "class": {
                                                Any(): {
                                                    Optional("bandwidth"): int,
                                                    Optional("random_detect"): {
                                                        "precedence": list,
                                                        "bytes1": list,
                                                        "bytes2": list,
                                                        "bytes3": list,
                                                    },
                                                },
                                            },
                                        },
                                    },
                                    Optional("qos_set"): {
                                        Optional("mpls_experimental_imposition"): int,
                                        Any(): {
                                            Any(): {
                                                Optional("packets_marked"): int,
                                                Optional("marker_statistics"): str,
                                            },
                                        },
                                    },
                                    Optional("police"): {
                                        Optional("cir_bps"): int,
                                        Optional("pir_bps"): int,
                                        Optional("cir_bc_bytes"): int,
                                        Optional("cir_be_bytes"): int,
                                        Optional("pir_bc_bytes"): int,
                                        Optional("pir_be_bytes"): int,
                                        Optional("rate_bps"): int,
                                        Optional("burst_bytes"): int,
                                        Optional("police_bps"): int,
                                        Optional("police_limit"): int,
                                        Optional("extended_limit"): int,
                                        Optional("bandwidth_remaining_ratio"): int,
                                        Optional("conformed"): {
                                            Optional("packets"): int,
                                            "bytes": int,
                                            "bps": int,
                                            Optional("actions"): {
                                                Any(): Or(bool, str),
                                            },
                                        },
                                        Optional("exceeded"): {
                                            Optional("packets"): int,
                                            "bytes": int,
                                            "bps": int,
                                            Optional("actions"): {
                                                Any(): Or(bool, str),
                                            },
                                        },
                                        Optional("violated"): {
                                            Optional("packets"): int,
                                            "bytes": int,
                                            "bps": int,
                                            Optional("actions"): {
                                                Any(): Or(bool, str),
                                            },
                                        },
                                    },
                                    Optional("afd_wred_stats"): {
                                        "virtual_class": {
                                            Any(): {
                                                "dscp": int,
                                                "min": int,
                                                "max": int,
                                                "transmit_bytes": int,
                                                "transmit_packets": int,
                                                "random_drop_bytes": int,
                                                "random_drop_packets": int,
                                                "afd_weight": int,
                                            }
                                        },
                                        "total_drops_bytes": int,
                                        "total_drops_packets": int,
                                    },
                                    Optional("child_policy_name"): {
                                        Any(): {
                                            Optional("class_map"): {
                                                Any(): {
                                                    "match_evaluation": str,
                                                    "match": list,
                                                    Optional("packets"): int,
                                                    Optional("packet_output"): int,
                                                    Optional("packet_drop"): int,
                                                    Optional("tail_random_drops"): int,
                                                    Optional("other_drops"): int,
                                                    Optional("bytes"): int,
                                                    Optional("queueing"): bool,
                                                    Optional(
                                                        "queue_limit_packets"
                                                    ): str,
                                                    Optional("queue_size"): int,
                                                    Optional("queue_limit"): int,
                                                    Optional("queue_limit_bytes"): int,
                                                    Optional("queue_limit_us"): int,
                                                    Optional("queue_depth"): int,
                                                    Optional("total_drops"): int,
                                                    Optional("no_buffer_drops"): int,
                                                    Optional("pkts_output"): int,
                                                    Optional("bytes_output"): int,
                                                    Optional("pkts_matched"): int,
                                                    Optional("bytes_matched"): int,
                                                    Optional("pkts_queued"): int,
                                                    Optional("bytes_queued"): int,
                                                    Optional("shape_type"): str,
                                                    Optional("shape_cir_bps"): int,
                                                    Optional("shape_bc_bps"): int,
                                                    Optional("shape_be_bps"): int,
                                                    Optional("target_shape_rate"): int,
                                                    Optional("output_queue"): str,
                                                    Optional("bandwidth_percent"): int,
                                                    Optional("bandwidth_kbps"): int,
                                                    Optional("bandwidth"): str,
                                                    Optional(
                                                        "bandwidth_remaining_ratio"
                                                    ): int,
                                                    Optional(
                                                        "bandwidth_remaining_percent"
                                                    ): int,
                                                    Optional(
                                                        "fair_queue_limit_per_flow"
                                                    ): int,
                                                    Optional(
                                                        "bandwidth_max_threshold_packets"
                                                    ): int,
                                                    Optional("priority_level"): int,
                                                    Optional(
                                                        "overhead_accounting"
                                                    ): str,
                                                    Optional("random_detect"): {
                                                        Optional(
                                                            "exp_weight_constant"
                                                        ): str,
                                                        Optional(
                                                            "exponential_weight"
                                                        ): str,
                                                        Optional(
                                                            "mean_queue_depth"
                                                        ): int,
                                                        Optional("class"): {
                                                            Any(): {
                                                                "transmitted_packets": str,
                                                                "transmitted_bytes": str,
                                                                "random_drop_packets": str,
                                                                "random_drop_bytes": str,
                                                                "tail_drop_packets": str,
                                                                "tail_drop_bytes": str,
                                                                "minimum_thresh": str,
                                                                "maximum_thresh": str,
                                                                "mark_prob": str,
                                                                Optional(
                                                                    "ecn_mark"
                                                                ): str,
                                                            },
                                                        },
                                                    },
                                                    Optional("priority"): {
                                                        Optional("percent"): int,
                                                        Optional("kbps"): int,
                                                        Optional("burst_bytes"): int,
                                                        Optional("exceed_drops"): int,
                                                        Optional("type"): str,
                                                    },
                                                    Optional("rate"): {
                                                        Optional("interval"): int,
                                                        Optional(
                                                            "offered_rate_bps"
                                                        ): int,
                                                        Optional("drop_rate_bps"): int,
                                                    },
                                                    Optional("policy"): {
                                                        Any(): {
                                                            "class": {
                                                                Any(): {
                                                                    Optional(
                                                                        "bandwidth"
                                                                    ): int,
                                                                    Optional(
                                                                        "random_detect"
                                                                    ): {
                                                                        "precedence": list,
                                                                        "bytes1": list,
                                                                        "bytes2": list,
                                                                        "bytes3": list,
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    },
                                                    Optional("qos_set"): {
                                                        Optional(
                                                            "mpls_experimental_imposition"
                                                        ): int,
                                                        Any(): {
                                                            Any(): {
                                                                Optional(
                                                                    "packets_marked"
                                                                ): int,
                                                                Optional(
                                                                    "marker_statistics"
                                                                ): str,
                                                            },
                                                        },
                                                    },
                                                    Optional("police"): {
                                                        Optional("cir_bps"): int,
                                                        Optional("pir_bps"): int,
                                                        Optional("cir_bc_bytes"): int,
                                                        Optional("cir_be_bytes"): int,
                                                        Optional("pir_bc_bytes"): int,
                                                        Optional("pir_be_bytes"): int,
                                                        Optional("police_bps"): int,
                                                        Optional("police_limit"): int,
                                                        Optional("extended_limit"): int,
                                                        Optional("rate_bps"): int,
                                                        Optional("burst_bytes"): int,
                                                        Optional(
                                                            "bandwidth_remaining_ratio"
                                                        ): int,
                                                        Optional("conformed"): {
                                                            Optional("packets"): int,
                                                            "bytes": int,
                                                            "bps": int,
                                                            Optional("actions"): {
                                                                Any(): Or(bool, str),
                                                            },
                                                        },
                                                        Optional("exceeded"): {
                                                            Optional("packets"): int,
                                                            "bytes": int,
                                                            "bps": int,
                                                            Optional("actions"): {
                                                                Any(): Or(bool, str),
                                                            },
                                                        },
                                                        Optional("violated"): {
                                                            Optional("packets"): int,
                                                            "bytes": int,
                                                            "bps": int,
                                                            Optional("actions"): {
                                                                Any(): Or(bool, str),
                                                            },
                                                        },
                                                    },
                                                    Optional("afd_wred_stats"): {
                                                        "virtual_class": {
                                                            Any(): {
                                                                "dscp": int,
                                                                "min": int,
                                                                "max": int,
                                                                "transmit_bytes": int,
                                                                "transmit_packets": int,
                                                                "random_drop_bytes": int,
                                                                "random_drop_packets": int,
                                                                "afd_weight": int,
                                                            }
                                                        },
                                                        "total_drops_bytes": int,
                                                        "total_drops_packets": int,
                                                    },
                                                    Optional("child_policy_name"): {
                                                        Any(): {
                                                            Optional("class_map"): {
                                                                Any(): {
                                                                    "match_evaluation": str,
                                                                    "match": list,
                                                                    Optional(
                                                                        "packets"
                                                                    ): int,
                                                                    Optional(
                                                                        "packet_output"
                                                                    ): int,
                                                                    Optional(
                                                                        "packet_drop"
                                                                    ): int,
                                                                    Optional(
                                                                        "tail_random_drops"
                                                                    ): int,
                                                                    Optional(
                                                                        "other_drops"
                                                                    ): int,
                                                                    Optional(
                                                                        "bytes"
                                                                    ): int,
                                                                    Optional(
                                                                        "queueing"
                                                                    ): bool,
                                                                    Optional(
                                                                        "queue_limit_packets"
                                                                    ): str,
                                                                    Optional(
                                                                        "queue_size"
                                                                    ): int,
                                                                    Optional(
                                                                        "queue_limit"
                                                                    ): int,
                                                                    Optional(
                                                                        "queue_limit_bytes"
                                                                    ): int,
                                                                    Optional(
                                                                        "queue_limit_us"
                                                                    ): int,
                                                                    Optional(
                                                                        "queue_depth"
                                                                    ): int,
                                                                    Optional(
                                                                        "total_drops"
                                                                    ): int,
                                                                    Optional(
                                                                        "no_buffer_drops"
                                                                    ): int,
                                                                    Optional(
                                                                        "pkts_output"
                                                                    ): int,
                                                                    Optional(
                                                                        "bytes_output"
                                                                    ): int,
                                                                    Optional(
                                                                        "pkts_matched"
                                                                    ): int,
                                                                    Optional(
                                                                        "bytes_matched"
                                                                    ): int,
                                                                    Optional(
                                                                        "pkts_queued"
                                                                    ): int,
                                                                    Optional(
                                                                        "bytes_queued"
                                                                    ): int,
                                                                    Optional(
                                                                        "shape_type"
                                                                    ): str,
                                                                    Optional(
                                                                        "shape_cir_bps"
                                                                    ): int,
                                                                    Optional(
                                                                        "shape_bc_bps"
                                                                    ): int,
                                                                    Optional(
                                                                        "shape_be_bps"
                                                                    ): int,
                                                                    Optional(
                                                                        "target_shape_rate"
                                                                    ): int,
                                                                    Optional(
                                                                        "output_queue"
                                                                    ): str,
                                                                    Optional(
                                                                        "bandwidth_percent"
                                                                    ): int,
                                                                    Optional(
                                                                        "bandwidth_kbps"
                                                                    ): int,
                                                                    Optional(
                                                                        "bandwidth"
                                                                    ): str,
                                                                    Optional(
                                                                        "bandwidth_remaining_ratio"
                                                                    ): int,
                                                                    Optional(
                                                                        "bandwidth_remaining_percent"
                                                                    ): int,
                                                                    Optional(
                                                                        "fair_queue_limit_per_flow"
                                                                    ): int,
                                                                    Optional(
                                                                        "bandwidth_max_threshold_packets"
                                                                    ): int,
                                                                    Optional(
                                                                        "priority_level"
                                                                    ): int,
                                                                    Optional(
                                                                        "overhead_accounting"
                                                                    ): str,
                                                                    Optional(
                                                                        "random_detect"
                                                                    ): {
                                                                        Optional(
                                                                            "exp_weight_constant"
                                                                        ): str,
                                                                        Optional(
                                                                            "exponential_weight"
                                                                        ): str,
                                                                        Optional(
                                                                            "mean_queue_depth"
                                                                        ): int,
                                                                        Optional(
                                                                            "class"
                                                                        ): {
                                                                            Any(): {
                                                                                "transmitted_packets": str,
                                                                                "transmitted_bytes": str,
                                                                                "random_drop_packets": str,
                                                                                "random_drop_bytes": str,
                                                                                "tail_drop_packets": str,
                                                                                "tail_drop_bytes": str,
                                                                                "minimum_thresh": str,
                                                                                "maximum_thresh": str,
                                                                                "mark_prob": str,
                                                                                Optional(
                                                                                    "ecn_mark"
                                                                                ): str,
                                                                            },
                                                                        },
                                                                    },
                                                                    Optional(
                                                                        "priority"
                                                                    ): {
                                                                        Optional(
                                                                            "percent"
                                                                        ): int,
                                                                        Optional(
                                                                            "kbps"
                                                                        ): int,
                                                                        Optional(
                                                                            "burst_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "exceed_drops"
                                                                        ): int,
                                                                        Optional(
                                                                            "type"
                                                                        ): str,
                                                                    },
                                                                    Optional("rate"): {
                                                                        Optional(
                                                                            "interval"
                                                                        ): int,
                                                                        Optional(
                                                                            "offered_rate_bps"
                                                                        ): int,
                                                                        Optional(
                                                                            "drop_rate_bps"
                                                                        ): int,
                                                                    },
                                                                    Optional(
                                                                        "policy"
                                                                    ): {
                                                                        Any(): {
                                                                            "class": {
                                                                                Any(): {
                                                                                    Optional(
                                                                                        "bandwidth"
                                                                                    ): int,
                                                                                    Optional(
                                                                                        "random_detect"
                                                                                    ): {
                                                                                        "precedence": list,
                                                                                        "bytes1": list,
                                                                                        "bytes2": list,
                                                                                        "bytes3": list,
                                                                                    },
                                                                                },
                                                                            },
                                                                        },
                                                                    },
                                                                    Optional(
                                                                        "qos_set"
                                                                    ): {
                                                                        Optional(
                                                                            "mpls_experimental_imposition"
                                                                        ): int,
                                                                        Any(): {
                                                                            Any(): {
                                                                                Optional(
                                                                                    "packets_marked"
                                                                                ): int,
                                                                                Optional(
                                                                                    "marker_statistics"
                                                                                ): str,
                                                                            },
                                                                        },
                                                                    },
                                                                    Optional(
                                                                        "police"
                                                                    ): {
                                                                        Optional(
                                                                            "cir_bps"
                                                                        ): int,
                                                                        Optional(
                                                                            "pir_bps"
                                                                        ): int,
                                                                        Optional(
                                                                            "cir_bc_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "cir_be_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "pir_bc_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "pir_be_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "police_bps"
                                                                        ): int,
                                                                        Optional(
                                                                            "police_limit"
                                                                        ): int,
                                                                        Optional(
                                                                            "extended_limit"
                                                                        ): int,
                                                                        Optional(
                                                                            "bandwidth_remaining_ratio"
                                                                        ): int,
                                                                        Optional(
                                                                            "conformed"
                                                                        ): {
                                                                            Optional(
                                                                                "packets"
                                                                            ): int,
                                                                            "bytes": int,
                                                                            "bps": int,
                                                                            Optional(
                                                                                "actions"
                                                                            ): {
                                                                                Any(): Or(
                                                                                    bool,
                                                                                    str,
                                                                                ),
                                                                            },
                                                                        },
                                                                        Optional(
                                                                            "exceeded"
                                                                        ): {
                                                                            Optional(
                                                                                "packets"
                                                                            ): int,
                                                                            "bytes": int,
                                                                            "bps": int,
                                                                            Optional(
                                                                                "actions"
                                                                            ): {
                                                                                Any(): Or(
                                                                                    bool,
                                                                                    str,
                                                                                ),
                                                                            },
                                                                        },
                                                                        Optional(
                                                                            "violated"
                                                                        ): {
                                                                            Optional(
                                                                                "packets"
                                                                            ): int,
                                                                            "bytes": int,
                                                                            "bps": int,
                                                                            Optional(
                                                                                "actions"
                                                                            ): {
                                                                                Any(): Or(
                                                                                    bool,
                                                                                    str,
                                                                                ),
                                                                            },
                                                                        },
                                                                    },
                                                                    Optional(
                                                                        "afd_wred_stats"
                                                                    ): {
                                                                        "virtual_class": {
                                                                            Any(): {
                                                                                "dscp": int,
                                                                                "min": int,
                                                                                "max": int,
                                                                                "transmit_bytes": int,
                                                                                "transmit_packets": int,
                                                                                "random_drop_bytes": int,
                                                                                "random_drop_packets": int,
                                                                                "afd_weight": int,
                                                                            }
                                                                        },
                                                                        "total_drops_bytes": int,
                                                                        "total_drops_packets": int,
                                                                    },
                                                                },
                                                            },
                                                            Optional(
                                                                "queue_stats_for_all_priority_classes"
                                                            ): {
                                                                Optional(
                                                                    "priority_level"
                                                                ): {
                                                                    Any(): {
                                                                        Optional(
                                                                            "queueing"
                                                                        ): bool,
                                                                        Optional(
                                                                            "queue_limit_packets"
                                                                        ): str,
                                                                        Optional(
                                                                            "queue_limit_bytes"
                                                                        ): int,
                                                                        Optional(
                                                                            "queue_limit_us"
                                                                        ): int,
                                                                        Optional(
                                                                            "queue_depth"
                                                                        ): int,
                                                                        Optional(
                                                                            "total_drops"
                                                                        ): int,
                                                                        Optional(
                                                                            "no_buffer_drops"
                                                                        ): int,
                                                                        Optional(
                                                                            "pkts_output"
                                                                        ): int,
                                                                        Optional(
                                                                            "bytes_output"
                                                                        ): int,
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                            Optional(
                                                "queue_stats_for_all_priority_classes"
                                            ): {
                                                Optional("priority_level"): {
                                                    Any(): {
                                                        Optional("queueing"): bool,
                                                        Optional(
                                                            "queue_limit_packets"
                                                        ): str,
                                                        Optional(
                                                            "queue_limit_bytes"
                                                        ): int,
                                                        Optional("queue_limit_us"): int,
                                                        Optional("queue_depth"): int,
                                                        Optional("total_drops"): int,
                                                        Optional(
                                                            "no_buffer_drops"
                                                        ): int,
                                                        Optional("pkts_output"): int,
                                                        Optional("bytes_output"): int,
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            Optional("queue_stats_for_all_priority_classes"): {
                                Optional("priority_level"): {
                                    Any(): {
                                        Optional("queueing"): bool,
                                        Optional("queue_limit_packets"): str,
                                        Optional("queue_limit_bytes"): int,
                                        Optional("queue_limit_us"): int,
                                        Optional("queue_depth"): int,
                                        Optional("total_drops"): int,
                                        Optional("no_buffer_drops"): int,
                                        Optional("pkts_output"): int,
                                        Optional("bytes_output"): int,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }

    BOOL_ACTION_LIST = ["drop", "transmit", "set_clp_transmit"]


class ShowPolicyMapTypeSuperParser(ShowPolicyMapTypeSchema):
    """Super Parser for
    * 'show policy-map interface {interface}',
    * 'show policy-map interface {interface} service instance {service_instance}',
    * 'show policy-map interface {interface} service instance {service_instance} input',
    * 'show policy-map interface {interface} service instance {service_instance} output',
    """

    def cli(self, interface="", service_instance="", output=None):

        # Init vars
        out = output
        ret_dict = {}
        class_line_type = None
        queue_stats = 0
        priority_dict = {}
        priority_level_status = False

        # To capture the length of whitespaces before start of the string
        p0 = re.compile(r"^(?P<whitespace>\s*)\S.*$")

        # Control Plane
        # GigabitEthernet0/1/5
        # Something else
        p1 = re.compile(
            r"^(?P<top_level>(Control Plane|Giga.*|FiveGiga.*|[Pp]seudo.*|Fast.*|[Ss]erial.*|"
            r"Ten.*|[Ee]thernet.*|[Tt]wentyFiveGigE.+|.+GigabitEthernet.+|FiftyGigE.+|[Tt]wenty.*|[Tt]en.*|[Ff]our.*|[Ff]ortyGigabit.*|[Tt]unnel.*|[Hh]undred.*|Port-channel\d+.\d+|Port-channel\d+))$"
        )

        # GigabitEthernet0/1/5 : Service Group 1
        p1_0 = re.compile(
            r"^(?P<top_level>(Giga.*)): +Service Group +(?P<service_group>(\d+))$"
        )

        # Port-channel1: Service Group 1
        p1_1 = re.compile(
            r"^(?P<top_level>([Pp]ort.*)): +Service Group +(?P<service_group>(\d+))$"
        )

        # Service-policy input: Control_Plane_In
        # Service-policy output: shape-out
        # Service-policy input:TEST
        p2 = re.compile(
            r"^[Ss]ervice-policy +(?P<service_policy>(input|output)):+ *(?P<policy_name>([\w\-]+).*)"
        )

        # service-policy : child
        p2_1 = re.compile(r"^Service-policy *:+ *(?P<policy_name>(.*))$")

        # Class-map: Ping_Class (match-all)
        # Class-map:TEST (match-all)
        # Class-map: TEST-OTTAWA_CANADA#PYATS (match-any)
        p3 = re.compile(
            r"^[Cc]lass-map *:( +)?(?P<class_map>\S+) +(?P<match_all>(.*))$"
        )

        # queue stats for all priority classes:
        p3_1 = re.compile(r"^queue +stats +for +all +priority +classes:$")

        # priority level 2
        p3_1_1 = re.compile(r"^priority +level +(?P<priority_level>(\d+))$")

        # 8 packets, 800 bytes
        p4 = re.compile(r"^(?P<packets>(\d+)) packets, (?P<bytes>(\d+)) +bytes$")

        # 8 packets
        p4_1 = re.compile(r"^(?P<packets>(\d+)) packets$")

        # 5 minute offered rate 0000 bps, drop rate 0000 bps
        p5 = re.compile(
            r"^(?P<interval>(\d+)) +minute +offered +rate +(?P<offered_rate>(\d+)) bps, +drop +rate +(?P<drop_rate>(\d+)) bps$"
        )

        # 5 minute offered rate 0000 bps
        # 5 minute rate 0 bps
        p5_1 = re.compile(
            r"^(?P<interval>(\d+)) +minute(offered| )+rate +(?P<offered_rate>(\d+)) bps$"
        )

        # 30 second offered rate 15000 bps, drop rate 300 bps
        p5_2 = re.compile(
            r"^(?P<interval>(\d+)) +second +offered +rate +(?P<offered_rate>(\d+)) bps, +drop +rate +(?P<drop_rate>(\d+)) bps$"
        )

        # Match: access-group name Ping_Option
        # Match: access-group name PYATS-MARKING_IN#CUSTOM__ACL
        p6 = re.compile(r"^[Mm]atch:( +)?(?P<match>([\S\s]+))$")

        # police:
        p7 = re.compile(r"^police:+$")

        #  police:  cir 64000 bps, bc 8000 bytes
        p7_1 = re.compile(
            r"^police: +cir (?P<cir_bps>(\d+)) bps, bc (?P<cir_bc_bytes>(\d+)) bytes$"
        )

        # cir 8000 bps, bc 1500 bytes
        p8 = re.compile(
            r"^cir (?P<cir_bps>(\d+)) bps, +bc +(?P<cir_bc_bytes>(\d+)) bytes$"
        )

        # 8000 bps, 1500 limit, 1500 extended limit
        p8_1 = re.compile(
            r"^(?P<police_bps>(\d+)) bps, +(?P<police_limit>(\d+)) limit, +"
            r"(?P<extended_limit>(\d+))(.*)$"
        )

        # cir 10000000 bps, be 312500 bytes
        p8_2 = re.compile(
            r"^cir (?P<cir_bps>(\d+)) bps, +be +(?P<cir_be_bytes>(\d+)) bytes$"
        )

        # pir 20000 bps, be 658 bytes
        p8_3 = re.compile(
            r"^pir (?P<pir_bps>(\d+)) bps, +be +(?P<pir_be_bytes>(\d+)) bytes$"
        )

        # pir 20000 bps, bc 658 bytes
        p8_4 = re.compile(
            r"^pir (?P<pir_bps>(\d+)) bps, +bc +(?P<pir_bc_bytes>(\d+)) bytes$"
        )

        # cir 10000000000 bps, bc 30000000 bytes, be 60000000 bytes
        p8_5 = re.compile(
            r"^cir (?P<cir_bps>(\d+)) bps, +bc +(?P<pir_bc_bytes>(\d+)) bytes, +be +(?P<cir_be_bytes>(\d+)) bytes$"
        )

        # rate 1000000000 bps, burst 1024000 bytes
        p8_6 = re.compile(
            r"^rate (?P<rate_bps>\d+) bps, burst (?P<burst_bytes>\d+) bytes$"
        )

        # conformed 8 packets, 800 bytes; actions:
        p9 = re.compile(
            r"^conformed (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes; actions:$"
        )

        # conformed 800 bytes; actions:
        p9_0 = re.compile(r"^conformed +(?P<bytes>\d+) bytes; actions:$")

        # conformed 15 packets, 6210 bytes; action:transmit
        p9_1 = re.compile(
            r"^conformed (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes;"
            r" action:(?P<action>(\w+))$"
        )

        # exceeded 0 packets, 0 bytes; actions:
        p10 = re.compile(
            r"^exceeded (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes; actions:$"
        )

        # exceeded 0 bytes; actions:
        p10_0 = re.compile(r"^exceeded +(?P<bytes>\d+) bytes; actions:$")

        # exceeded 5 packets, 5070 bytes; action:drop
        p10_1 = re.compile(
            r"^exceeded (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes;"
            r" action:(?P<action>(\w+))$"
        )

        # violated 0 packets, 0 bytes; action:drop
        p11 = re.compile(
            r"^violated (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes;"
            r" action:(?P<action>(\w+))$"
        )

        # violated 0 packets, 0 bytes; actions:
        p11_1 = re.compile(
            r"^violated (?P<packets>(\d+)) packets, +(?P<bytes>(\d+)) bytes; actions:$"
        )

        # violated 0 bytes; actions:
        p11_2 = re.compile(r"^violated +(?P<bytes>(\d+)) bytes; actions:$")

        # conformed 0000 bps, exceeded 0000 bps
        p12 = re.compile(
            r"^conformed +(?P<c_bps>(\d+)) bps, excee(ded|d) (?P<e_bps>(\d+)) bps$"
        )

        # conformed 0 bps, exceed 0 bps, violate 0 bps
        p12_1 = re.compile(
            r"^conformed +(?P<c_bps>(\d+)) bps,+ excee(d|ded) (?P<e_bps>(\d+)) bps, "
            r"violat(e|ed) (?P<v_bps>(\d+)) bps$"
        )

        # drop
        # transmit
        # start
        # set-qos-transmit 7
        # set-mpls-exp-imposition-transmit 7
        # set-dscp-transmit ef
        # filter 'Queueing' and 'random-detect'
        # set-dscp-transmit dscp table policed-dscp
        p13 = re.compile(
            r"^(?![Qr])(?P<action>drop|transmit|start|set-qos-transmit|set-mpls-exp-imposition-transmit|set-dscp-transmit|filter)( +(?P<value>.+))?$"
        )

        # QoS Set
        p14 = re.compile(r"^QoS +Set+$")

        # ip precedence 6
        # dscp af41
        # qos-group 20
        # dscp dscp table t1
        # traffic-class dscp table t1
        # cos cos table t1
        # traffic-class cos table t1
        p14_1 = re.compile(
            r"^(?P<key>(ip precedence|qos-group|dscp|cos|traffic-class)) +(?P<value>(\w+|(dscp table|cos table) \w+))$"
        )

        # Marker statistics: Disabled
        p14_2 = re.compile(r"^Marker +statistics: +(?P<marker_statistics>(\w+))$")

        # Packets marked 500
        p14_3 = re.compile(r"^Packets +marked +(?P<packets_marked>(\d+))$")

        # mpls experimental imposition 1
        p14_4 = re.compile(r"^mpls experimental imposition +(?P<value>.+)$")

        # Queueing
        p15 = re.compile(r"^Queueing$")

        # queue size 0, queue limit 4068
        p16 = re.compile(
            r"^queue +size +(?P<queue_size>(\d+)), +queue +limit +(?P<queue_limit>(\d+))$"
        )

        # queue limit 64 packets
        p17 = re.compile(r"^queue +limit +(?P<queue_limit>(\d+)) packets")

        # queue limit 62500 bytes
        p17_1 = re.compile(r"^queue +limit +(?P<queue_limit_bytes>(\d+)) bytes$")

        # (queue depth/total drops/no-buffer drops) 0/0/0
        p18 = re.compile(
            r"^\(+queue +depth/+total +drops/+no-buffer +drops+\) +(?P<queue_depth>(\d+))/"
            r"+(?P<total_drops>(\d+))/+(?P<no_buffer_drops>(\d+))$"
        )

        # depth/total drops/no-buffer drops) 147/38/0
        p18_1 = re.compile(
            r"^depth/+total +drops/+no-buffer +drops+\) +(?P<queue_depth>(\d+))/+"
            r"(?P<total_drops>(\d+))/+(?P<no_buffer_drops>(\d+))$"
        )

        # (pkts output/bytes output) 0/0
        p19 = re.compile(
            r"^\(+pkts +output/+bytes +output+\) +(?P<pkts_output>(\d+))/+(?P<bytes_output>(\d+))$"
        )

        # (pkts matched/bytes matched) 363/87120
        p19_0 = re.compile(
            r"^\(+pkts +matched/+bytes +matched+\) +(?P<pkts_matched>(\d+))/+(?P<bytes_matched>(\d+))$"
        )

        # (pkts queued/bytes queued) 0/0
        p19_1 = re.compile(
            r"^\(+pkts +queued/+bytes +queued+\) +(?P<pkts_queued>(\d+))/+(?P<bytes_queued>(\d+))$"
        )

        # shape (average) cir 474656, bc 1899, be 1899
        p20 = re.compile(
            r"^shape +\(+(?P<shape_type>(\w+))+\) +cir +(?P<shape_cir_bps>(\d+)), +"
            r"bc +(?P<shape_bc_bps>(\d+)), +be +(?P<shape_be_bps>(\d+))$"
        )

        # target shape rate 474656
        p21 = re.compile(r"^target +shape +rate +(?P<target_shape_rate>(\d+))$")

        # Output Queue: Conversation 266
        p22 = re.compile(r"^Output +Queue: +(?P<output_queue>([\w\s]+))$")

        # Bandwidth 10 (%)
        p23 = re.compile(r"^Bandwidth +(?P<bandwidth>(\d+)) .*$")

        # bandwidth 1000 (kbps)
        p24 = re.compile(r"^bandwidth (?P<bandwidth_kbps>(\d+)) \(?kbps\)?$")

        # bandwidth 5% (234 kbps)
        p24_1 = re.compile(
            r"^bandwidth (?P<bandwidth_percent>(\d+))\% +\((?P<bandwidth_kbps>(\d+)) +kbps\)$"
        )

        # exponential weight: 9
        # exponential weight:9
        # Exp-weight-constant: 9 (1/512)
        # Exp-weight-constant:9 (1/512)
        p25 = re.compile(
            r"^(?P<key>(Exp-weight-constant|exponential.*)):+ *(?P<value>([\w\(\)\s\/]+))"
        )

        # mean queue depth: 25920
        # Mean queue depth: 0 bytes
        # Mean queue depth:0
        p26 = re.compile(r"^(M|m)ean +queue +depth:+ *(?P<mean_queue_depth>(\d+))")

        # class     Transmitted       Random drop      Tail drop     Minimum Maximum Mark
        # class     Transmitted       Random drop      Tail drop     Minimum Maximum Mark
        # dscp      Transmitted       Random drop      Tail drop     Minimum Maximum Mark
        p27_1 = re.compile(
            r"^(class|dscp) +Transmitted +Random +drop +(Tail|Tail/Flow) +drop +Minimum +Maximum +Mark$"
        )

        # Class  Random    Tail    Minimum    Maximum     Mark      Output
        p27_2 = re.compile(r"^Class +Random +Tail +Minimum +Maximum +Mark +Output$")

        # class     Transmitted       Random drop      Tail drop     Minimum Maximum Mark
        #   0             0/0               0/0               0/0      20000    40000  1/10
        #   1           328/78720          38/9120            0/0      22000    40000  1/10
        #   2             0/0               0/0               0/0      24000    40000  1/10
        #   3             0/0               0/0               0/0      26000    40000  1/10
        #   4             0/0               0/0               0/0      28000    40000  1/10
        # Class         Random             Tail            Minimum    Maximum   Mark   Output
        #   0             0                 0                 0        0        1/10   0
        p27 = re.compile(
            r"^(?P<class>(\w+)) +(?P<value1_pkts>(\d+))/+(?P<value1_bytes>(\d+)) +"
            r"(?P<value2_pkts>(\d+))/+(?P<value2_bytes>(\d+)) +"
            r"(?P<value3_pkts>(\d+))/+(?P<value3_bytes>(\d+)) +"
            r"(?P<value4>([\d\/]+)) +(?P<value5>([\d\/]+)) +(?P<value6>([\d\/]+))$"
        )

        # policy wred-policy
        p28 = re.compile(r"^policy +(?P<policy>([\w\-]+))$")

        # class prec2
        p29 = re.compile(r"^class +(?P<class>([\w\-]+))$")

        # bandwidth 1000
        p30 = re.compile(r"^bandwidth +(?P<bandwidth>(\d+))$")

        # bandwidth remaining ratio 1
        p31 = re.compile(
            r"^bandwidth +remaining +ratio +(?P<bandwidth_remaining_ratio>(\d+))$"
        )

        # bandwidth:class-based wfq, weight 25
        p32 = re.compile(r"^bandwidth(:| )?(?P<bandwidth>([\s\w\-\,]+))$")

        # random-detect
        p33 = re.compile(r"^random-detect$")

        # random-detect precedence 2 100 bytes 200 bytes 10
        p33_1 = re.compile(
            r"^random-detect +precedence +(?P<precedence>(\d+)) +"
            r"(?P<bytes1>(\d+)) bytes +(?P<bytes2>(\d+)) bytes +(?P<bytes3>(\d+))$"
        )

        # packet output 90, packet drop 0
        p34 = re.compile(
            r"^packet +output +(?P<packet_output>(\d+)), +packet +drop +(?P<packet_drop>(\d+))$"
        )

        # tail/random drop 0, no buffer drop 0, other drop 0
        p35 = re.compile(
            r"^tail/random drop +(?P<tail_random_drops>(\d+)), +no buffer drop +(?P<no_buffer_drops>(\d+)), "
            r"+other drop +(?P<other_drops>(\d+))$"
        )

        # queue limit 1966 us/ 49152 bytes
        p36 = re.compile(
            r"^queue +limit +(?P<queue_limit_us>(\d+)) +us/ +(?P<queue_limit_bytes>(\d+)) bytes$"
        )

        # Priority: 10% (100000 kbps), burst bytes 2500000, b/w exceed drops: 44577300
        p37 = re.compile(
            r"^Priority:\s+(?P<percent>(\d+))%\s+\((?P<kbps>(\d+))\s+kbps\),\s+burst\sbytes\s+(?P<burst_bytes>(\d)+),(\s+"
            r"b/w\sexceed\sdrops:\s+(?P<exceed_drops>(\d+)))?$"
        )

        # Priority Level: 1
        p38 = re.compile(r"^Priority +Level: +(?P<priority_level>(\d+))$")

        # bandwidth remaining 70%
        p39 = re.compile(
            r"^bandwidth +remaining +(?P<bandwidth_remaining_percent>(\d+))%$"
        )

        # Priority: Strict, b/w exceed drops: 0
        p40 = re.compile(
            r"^Priority: +(?P<type>(\w+)), +b/w exceed drops: +(?P<exceed_drops>(\d+))$"
        )

        # cos 5
        # traffic-class 6
        p41 = re.compile(r"^(?P<key>cos|traffic\-class)\s+(?P<value>\d+)$")

        # Virtual Class   min/max        Transmit                 Random drop                 AFD Weight
        #       0         10 / 20    (Byte)33459183360             27374016                     12
        p42 = re.compile(
            r"^(?P<virtual_class>\d+)\s+(?P<min>\d+)\s*/\s*(?P<max>\d+)\s+\(Byte\)(?P<tx_bytes>\d+)\s+(?P<random_drop_bytes>\d+)\s+(?P<afd_weight>\d+)\s*$"
        )

        #                                (Pkts)68692637637             0
        p43 = re.compile(r"^\(Pkts\)(?P<tx_packets>\d+)\s+(?P<random_drop_packets>\d+)")

        #         dscp : 1
        p44 = re.compile(r"^dscp\s*:\s*(?P<dscp>\d+)$")

        #     Total Drops(Bytes)   : 0
        p45 = re.compile(r"^Total Drops\(Bytes\)\s*:\s*(?P<total_drops_bytes>\d+)$")

        #     Total Drops(Packets) : 0
        p46 = re.compile(r"^Total Drops\(Packets\)\s*:\s*(?P<total_drops_packets>\d+)$")

        # (total drops) 0
        p47 = re.compile(r"^\(total +drops\) +(?P<total_drops>(\d+))$")

        # (bytes output) 3392
        p48 = re.compile(r"^\(bytes +output\) +(?P<bytes_output>(\d+))$")

        # Overhead Accounting Enabled
        p49 = re.compile(r"Overhead +Accounting +(?P<enabled>([\w\-]+))$")

        # Fair-queue: per-flow queue limit 128 packets
        p50 = re.compile(
            r"^Fair-queue: +per-flow +queue +limit +(?P<queue_limit>\d+) +packets$"
        )

        # -1 depth since the top policy-map is a child element, but has depth 0
        dict_stack = [(-1, ret_dict)]

        for line in out.splitlines():

            m = p0.match(line)
            if m:
                # get length of prepended whitespace
                len_white = len(m.groupdict()["whitespace"])

            else:
                # no contents in this line, skip
                continue

            line = line.strip()
            if not line:
                continue

            # Control Plane
            # GigabitEthernet9/5: Service Group 1
            m = p1_0.match(line) or p1.match(line)
            if m:

                top_level = m.groupdict()["top_level"]
                # check if previous dict on stack is more deeply nested than the current item
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                top_level_dict = ret_dict.setdefault(top_level, {})
                dict_stack.append(
                    (
                        len_white,
                        top_level_dict,
                    )
                )
                if "service_group" in m.groupdict():
                    top_level_dict["service_group"] = int(
                        m.groupdict()["service_group"]
                    )
                continue

            # Port-channel1: Service Group 1
            m = p1_1.match(line)
            if m:
                top_level = m.groupdict()["top_level"]
                # check if previous dict on stack is more deeply nested than the current item
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                top_level_dict = ret_dict.setdefault(top_level, {})
                dict_stack.append(
                    (
                        len_white,
                        top_level_dict,
                    )
                )
                if "service_group" in m.groupdict():
                    top_level_dict["service_group"] = int(
                        m.groupdict()["service_group"]
                    )
                continue

            # Service-policy input: Control_Plane_In
            # Service-policy output: Control_Plane_Out
            m = p2.match(line)
            if m:
                try:
                    top_level_dict
                except UnboundLocalError:
                    top_level_dict = ret_dict.setdefault(interface, {})
                    dict_stack.append(
                        (
                            len_white,
                            top_level_dict,
                        )
                    )

                service_policy = m.groupdict()["service_policy"]
                policy_name = m.groupdict()["policy_name"]

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                service_policy_dict = top_level_dict.setdefault(
                    "service_policy", {}
                ).setdefault(service_policy, {})
                dict_stack.append(
                    (
                        len_white,
                        service_policy_dict,
                    )
                )
                policy_dict = service_policy_dict.setdefault(
                    "policy_name", {}
                ).setdefault(policy_name, {})
                dict_stack.append(
                    (
                        len_white,
                        policy_dict,
                    )
                )
                continue

            # Service policy : child
            m = p2_1.match(line)
            if m:

                child_policy = m.groupdict()["policy_name"]
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                class_map_dict = dict_stack[-1][1]
                child_dict = class_map_dict.setdefault(
                    "child_policy_name", {}
                ).setdefault(child_policy, {})
                dict_stack.append(
                    (
                        len_white,
                        child_dict,
                    )
                )
                continue

            # Class-map: Ping_Class (match-all)
            # Class-map:TEST (match-all)
            # Class-map: TEST-OTTAWA_CANADA#PYATS (match-any)
            m = p3.match(line)
            if m:

                match_list = []
                class_line_type = None
                queue_stats = 0
                class_map = m.groupdict()["class_map"]
                class_match = (
                    m.groupdict()["match_all"].replace("(", "").replace(")", "")
                )

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                # add class_map to whatever dict is on the stack.
                class_dict = (
                    dict_stack[-1][1]
                    .setdefault("class_map", {})
                    .setdefault(class_map, {})
                )
                dict_stack.append(
                    (
                        len_white,
                        class_dict,
                    )
                )
                class_dict["match_evaluation"] = class_match
                continue

            # queue stats for all priority classes:
            m = p3_1.match(line)
            if m:

                queue_stats = 1
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                queue_dict = policy_dict.setdefault(
                    "queue_stats_for_all_priority_classes", {}
                )
                dict_stack.append(
                    (
                        len_white,
                        queue_dict,
                    )
                )
                continue

            # priority level 2
            m = p3_1_1.match(line)
            if m:

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                priority_level_status = True
                priority_level = m.groupdict()["priority_level"]
                priority_dict = queue_dict.setdefault("priority_level", {}).setdefault(
                    priority_level, {}
                )
                priority_dict["queueing"] = queueing_val
                continue

            # 8 packets, 800 bytes
            m = p4.match(line)
            if m:

                pkts = m.groupdict()["packets"]
                byte = m.groupdict()["bytes"]
                class_dict.setdefault("packets", int(pkts))
                class_dict.setdefault("bytes", int(byte))
                continue

            # 8 packets
            m = p4_1.match(line)
            if m:

                pkts = m.groupdict()["packets"]
                class_dict.setdefault("packets", int(pkts))
                continue

            # 5 minute offered rate 0000 bps, drop rate 0000 bps
            m = p5.match(line)
            if m:

                rate_dict = class_dict.setdefault("rate", {})
                dict_stack.append(
                    (
                        len_white,
                        rate_dict,
                    )
                )

                rate_dict["interval"] = int(m.groupdict()["interval"]) * 60
                rate_dict["offered_rate_bps"] = int(m.groupdict()["offered_rate"])
                rate_dict["drop_rate_bps"] = int(m.groupdict()["drop_rate"])
                continue

            # 5 minute offered rate 0000 bps
            m = p5_1.match(line)
            if m:

                rate_dict = class_dict.setdefault("rate", {})
                dict_stack.append(
                    (
                        len_white,
                        rate_dict,
                    )
                )
                rate_dict["interval"] = int(m.groupdict()["interval"]) * 60
                rate_dict["offered_rate_bps"] = int(m.groupdict()["offered_rate"])
                continue

            # 30 second offered rate 15000 bps, drop rate 300 bps
            m = p5_2.match(line)
            if m:

                rate_dict = class_dict.setdefault("rate", {})
                dict_stack.append(
                    (
                        len_white,
                        rate_dict,
                    )
                )
                rate_dict["interval"] = int(m.groupdict()["interval"])
                rate_dict["offered_rate_bps"] = int(m.groupdict()["offered_rate"])
                rate_dict["drop_rate_bps"] = int(m.groupdict()["drop_rate"])
                continue

            # Match: access-group name Ping_Option
            # Match: access-group name PYATS-MARKING_IN#CUSTOM__ACL

            m = p6.match(line)
            if m:

                # check if previous dict on stack is more deeply nested than the current item
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                match_list.append(m.groupdict()["match"])
                class_dict.setdefault("match", match_list)
                continue

            # police:
            m = p7.match(line)
            if m:

                police_dict = class_dict.setdefault("police", {})
                dict_stack.append(
                    (
                        len_white,
                        police_dict,
                    )
                )
                continue

            # police:  cir 64000 bps, bc 8000 bytes
            m = p7_1.match(line)
            if m:

                police_dict = class_dict.setdefault("police", {})
                dict_stack.append(
                    (
                        len_white,
                        police_dict,
                    )
                )
                police_dict["cir_bps"] = int(m.groupdict()["cir_bps"])
                police_dict["cir_bc_bytes"] = int(m.groupdict()["cir_bc_bytes"])
                continue

            # cir 8000 bps, bc 1500 bytes
            m = p8.match(line)
            if m:

                police_dict["cir_bps"] = int(m.groupdict()["cir_bps"])
                police_dict["cir_bc_bytes"] = int(m.groupdict()["cir_bc_bytes"])
                continue

            # 8000 bps, 1500 limit, 1500 extended limit
            m = p8_1.match(line)
            if m:
                police_dict["police_bps"] = int(m.groupdict()["police_bps"])
                police_dict["police_limit"] = int(m.groupdict()["police_limit"])
                police_dict["extended_limit"] = int(m.groupdict()["extended_limit"])
                continue

            # cir 10000000 bps, be 312500 bytes
            m = p8_2.match(line)
            if m:
                police_dict["cir_bps"] = int(m.groupdict()["cir_bps"])
                police_dict["cir_be_bytes"] = int(m.groupdict()["cir_be_bytes"])
                continue

            # pir 20000 bps, be 658 bytes
            m = p8_3.match(line)
            if m:
                police_dict["pir_bps"] = int(m.groupdict()["pir_bps"])
                police_dict["pir_be_bytes"] = int(m.groupdict()["pir_be_bytes"])
                continue

            # pir 20000 bps, bc 658 bytes
            m = p8_4.match(line)
            if m:
                police_dict["pir_bps"] = int(m.groupdict()["pir_bps"])
                police_dict["pir_bc_bytes"] = int(m.groupdict()["pir_bc_bytes"])
                continue

            # cir 10000000000 bps, bc 30000000 bytes, be 60000000 bytes
            m = p8_5.match(line)
            if m:
                police_dict["cir_bps"] = int(m.groupdict()["cir_bps"])
                police_dict["pir_bc_bytes"] = int(m.groupdict()["pir_bc_bytes"])
                police_dict["cir_be_bytes"] = int(m.groupdict()["cir_be_bytes"])
                continue

            # rate 1000000000 bps, burst 1024000 bytes
            m = p8_6.match(line)
            if m:
                police_dict["rate_bps"] = int(m.groupdict()["rate_bps"])
                police_dict["burst_bytes"] = int(m.groupdict()["burst_bytes"])
                continue

            # conformed 8 packets, 800 bytes; actions:
            m = p9.match(line)
            if m:

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                conformed_line = True
                exceeded_line = False
                violated_line = False
                conformed_dict = police_dict.setdefault("conformed", {})
                dict_stack.append(
                    (
                        len_white,
                        conformed_dict,
                    )
                )
                conformed_dict["packets"] = int(m.groupdict()["packets"])
                conformed_dict["bytes"] = int(m.groupdict()["bytes"])
                conf_action_dict = conformed_dict.setdefault("actions", {})
                dict_stack.append(
                    (
                        len_white,
                        conf_action_dict,
                    )
                )
                continue

            # conformed 0 bytes; actions:
            m = p9_0.match(line)
            if m:
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                conformed_line = True
                exceeded_line = False
                violated_line = False
                conformed_dict = police_dict.setdefault("conformed", {})
                dict_stack.append(
                    (
                        len_white,
                        conformed_dict,
                    )
                )
                conformed_dict["bytes"] = int(m.groupdict()["bytes"])
                conf_action_dict = conformed_dict.setdefault("actions", {})
                dict_stack.append(
                    (
                        len_white,
                        conf_action_dict,
                    )
                )
                continue

            # conformed 15 packets, 6210 bytes; action:transmit
            m = p9_1.match(line)
            if m:
                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()
                conformed_dict = police_dict.setdefault("conformed", {})
                dict_stack.append(
                    (
                        len_white,
                        conformed_dict,
                    )
                )
                conformed_dict["packets"] = int(m.groupdict()["packets"])
                conformed_dict["bytes"] = int(m.groupdict()["bytes"])
                conf_action_dict = conformed_dict.setdefault("actions", {})
                dict_stack.append(
                    (
                        len_white,
                        conf_action_dict,
                    )
                )
                action = m.groupdict()["action"]
                conf_action_dict.update({action: True})
                continue

            # exceeded 0 packets, 0 bytes; actions:
            m = p10.match(line)
            if m:

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                conformed_line = False
                violated_line = False
                exceeded_line = True
                exceeded_dict = police_dict.setdefault("exceeded", {})
                exceeded_dict["packets"] = int(m.groupdict()["packets"])
                exceeded_dict["bytes"] = int(m.groupdict()["bytes"])
                exc_action_dict = exceeded_dict.setdefault("actions", {})
                continue

            # exceeded 0 bytes; actions:
            m = p10_0.match(line)
            if m:
                conformed_line = False
                violated_line = False
                exceeded_line = True
                exceeded_dict = police_dict.setdefault("exceeded", {})
                exceeded_dict["bytes"] = int(m.groupdict()["bytes"])
                exc_action_dict = exceeded_dict.setdefault("actions", {})
                continue

            # exceeded 5 packets, 5070 bytes; action:drop
            m = p10_1.match(line)
            if m:
                exceeded_dict = police_dict.setdefault("exceeded", {})
                exceeded_dict["packets"] = int(m.groupdict()["packets"])
                exceeded_dict["bytes"] = int(m.groupdict()["bytes"])
                exc_action_dict = exceeded_dict.setdefault("actions", {})
                action = m.groupdict()["action"]
                exc_action_dict.update({action: True})
                continue

            # violated 0 packets, 0 bytes; action:drop
            m = p11.match(line)
            if m:
                violated_dict = police_dict.setdefault("violated", {})
                violated_dict["packets"] = int(m.groupdict()["packets"])
                violated_dict["bytes"] = int(m.groupdict()["bytes"])
                viol_action_dict = violated_dict.setdefault("actions", {})
                action = m.groupdict()["action"]
                viol_action_dict.update({action: True})
                continue

            # violated 0 packets, 0 bytes; actions:
            m = p11_1.match(line)
            if m:
                conformed_line = False
                exceeded_line = False
                violated_line = True
                violated_dict = police_dict.setdefault("violated", {})
                violated_dict["packets"] = int(m.groupdict()["packets"])
                violated_dict["bytes"] = int(m.groupdict()["bytes"])
                viol_action_dict = violated_dict.setdefault("actions", {})
                continue

            # violated 0 bytes; actions:
            m = p11_2.match(line)
            if m:
                conformed_line = False
                exceeded_line = False
                violated_line = True
                violated_dict = police_dict.setdefault("violated", {})
                violated_dict["bytes"] = int(m.groupdict()["bytes"])
                viol_action_dict = violated_dict.setdefault("actions", {})
                continue

            # conformed 0000 bps, exceeded 0000 bps
            m = p12.match(line)
            if m:
                conformed_dict["bps"] = int(m.groupdict()["c_bps"])
                exceeded_dict["bps"] = int(m.groupdict()["e_bps"])
                continue

            # conformed 0 bps, exceed 0 bps, violate 0 bps
            m = p12_1.match(line)
            if m:
                conformed_dict["bps"] = int(m.groupdict()["c_bps"])
                exceeded_dict["bps"] = int(m.groupdict()["e_bps"])
                violated_dict["bps"] = int(m.groupdict()["v_bps"])
                continue

            # QoS Set
            m = p14.match(line)
            if m:
                qos_dict = class_dict.setdefault("qos_set", {})
                continue

            # ip precedence 6
            # cos 5
            m = p14_1.match(line) or p41.match(line)
            if m:

                while dict_stack[-1][0] >= len_white:
                    dict_stack.pop()

                group = m.groupdict()
                key = group["key"].strip()
                value = group["value"].strip()
                qos_dict_map = qos_dict.setdefault(key, {}).setdefault(value, {})
                continue

            # Marker statistics: Disabled
            m = p14_2.match(line)
            if m:
                qos_dict_map["marker_statistics"] = m.groupdict()["marker_statistics"]
                continue

            # Packets marked 500
            m = p14_3.match(line)
            if m:
                qos_dict_map["packets_marked"] = int(m.groupdict()["packets_marked"])
                continue

            # mpls experimental imposition 1
            m = p14_4.match(line)
            if m:
                qos_dict["mpls_experimental_imposition"] = int(m.groupdict()["value"])
                continue

            # drop
            # transmit
            # start
            # set-qos-transmit 7
            # set-mpls-exp-imposition-transmit 7
            m = p13.match(line)
            if m:
                action = m.groupdict()["action"].replace("-", "_")
                if action in self.BOOL_ACTION_LIST:
                    value = True
                else:
                    value = m.groupdict()["value"]
                try:
                    if conformed_line:
                        conf_action_dict.update({action: value})
                    elif exceeded_line:
                        exc_action_dict.update({action: value})
                    elif violated_line:
                        viol_action_dict.update({action: value})
                    continue
                except Exception as e:
                    pass

            # Queueing
            m = p15.match(line)
            if m:
                if queue_stats == 1:
                    queueing_val = True
                    # priority_dict['queueing'] = True
                else:
                    class_dict["queueing"] = True
                continue

            # queue size 0, queue limit 4068
            m = p16.match(line)
            if m:
                class_dict["queue_size"] = int(m.groupdict()["queue_size"])
                class_dict["queue_limit"] = int(m.groupdict()["queue_limit"])
                continue

            # queue limit 64 packets
            m = p17.match(line)
            if m:
                if queue_stats == 1:
                    if not priority_level_status:
                        priority_dict = (
                            dict_stack[-1][1]
                            .setdefault("priority_level", {})
                            .setdefault("default", {})
                        )
                        priority_dict["queueing"] = queueing_val
                    priority_dict["queue_limit_packets"] = m.groupdict()["queue_limit"]
                else:
                    class_dict["queue_limit_packets"] = m.groupdict()["queue_limit"]
                continue

            # queue limit 62500 bytes
            m = p17_1.match(line)
            if m:
                class_dict["queue_limit_bytes"] = int(
                    m.groupdict()["queue_limit_bytes"]
                )
                continue

            # (queue depth/total drops/no-buffer drops) 0/0/0
            m = p18.match(line)
            if m:
                if queue_stats == 1:
                    if not priority_dict:
                        priority_dict = (
                            dict_stack[-1][1]
                            .setdefault("priority_level", {})
                            .setdefault("default", {})
                        )
                    priority_dict["queue_depth"] = int(m.groupdict()["queue_depth"])
                    priority_dict["total_drops"] = int(m.groupdict()["total_drops"])
                    priority_dict["no_buffer_drops"] = int(
                        m.groupdict()["no_buffer_drops"]
                    )

                else:
                    class_dict["queue_depth"] = int(m.groupdict()["queue_depth"])
                    class_dict["total_drops"] = int(m.groupdict()["total_drops"])
                    class_dict["no_buffer_drops"] = int(
                        m.groupdict()["no_buffer_drops"]
                    )
                continue

            # depth/total drops/no-buffer drops) 147/38/0
            m = p18_1.match(line)
            if m:
                class_dict["queue_depth"] = int(m.groupdict()["queue_depth"])
                class_dict["total_drops"] = int(m.groupdict()["total_drops"])
                class_dict["no_buffer_drops"] = int(m.groupdict()["no_buffer_drops"])
                continue

            # (pkts output/bytes output) 0/0
            m = p19.match(line)
            if m:
                if queue_stats == 1:
                    priority_dict["pkts_output"] = int(m.groupdict()["pkts_output"])
                    priority_dict["bytes_output"] = int(m.groupdict()["bytes_output"])
                else:
                    class_dict["pkts_output"] = int(m.groupdict()["pkts_output"])
                    class_dict["bytes_output"] = int(m.groupdict()["bytes_output"])
                continue

            # (pkts matched/bytes matched) 363/87120
            m = p19_0.match(line)
            if m:
                class_dict["pkts_matched"] = int(m.groupdict()["pkts_matched"])
                class_dict["bytes_matched"] = int(m.groupdict()["bytes_matched"])
                continue

            # (pkts queued/bytes queued) 0/0
            m = p19_1.match(line)
            if m:
                class_dict["pkts_queued"] = int(m.groupdict()["pkts_queued"])
                class_dict["bytes_queued"] = int(m.groupdict()["bytes_queued"])
                continue

            # shape (average) cir 474656, bc 1899, be 1899
            m = p20.match(line)
            if m:
                class_dict["shape_type"] = m.groupdict()["shape_type"]
                class_dict["shape_cir_bps"] = int(m.groupdict()["shape_cir_bps"])
                class_dict["shape_bc_bps"] = int(m.groupdict()["shape_bc_bps"])
                class_dict["shape_be_bps"] = int(m.groupdict()["shape_be_bps"])
                continue

            # target shape rate 474656
            m = p21.match(line)
            if m:
                class_dict["target_shape_rate"] = int(
                    m.groupdict()["target_shape_rate"]
                )
                continue

            # Output Queue: Conversation 266
            m = p22.match(line)
            if m:
                class_dict["output_queue"] = m.groupdict()["output_queue"]
                continue

            # Bandwidth 10 (%)
            m = p23.match(line)
            if m:
                class_dict["bandwidth_percent"] = int(m.groupdict()["bandwidth"])
                continue

            # bandwidth 1000 (kbps)
            m = p24.match(line)
            if m:
                class_dict["bandwidth_kbps"] = int(m.groupdict()["bandwidth_kbps"])
                continue

            # bandwidth 1000 (kbps)
            m = p24_1.match(line)
            if m:
                class_dict["bandwidth_percent"] = int(
                    m.groupdict()["bandwidth_percent"]
                )
                class_dict["bandwidth_kbps"] = int(m.groupdict()["bandwidth_kbps"])
                continue

            # exponential weight: 9
            m = p25.match(line)
            if m:
                group = m.groupdict()
                key = group["key"].strip()
                value = group["value"].strip()
                random_detect_dict = class_dict.setdefault("random_detect", {})
                if key.startswith("exponential"):
                    random_detect_dict["exponential_weight"] = value
                else:
                    random_detect_dict["exp_weight_constant"] = value
                continue

            # mean queue depth: 25920
            # Mean queue depth: 0 bytes
            m = p26.match(line)
            if m:
                random_detect_dict["mean_queue_depth"] = int(
                    m.groupdict()["mean_queue_depth"]
                )
                continue

            # class     Transmitted       Random drop      Tail drop     Minimum Maximum Mark
            m = p27_1.match(line)
            if m:
                class_line_type = 1
                continue

            # Class Random       Tail    Minimum    Maximum     Mark      Output
            m = p27_2.match(line)
            if m:
                class_line_type = 2
                continue

            # class     Transmitted       Random drop      Tail drop     Minimum Maximum Mark
            #           pkts/bytes        pkts/bytes       pkts/bytes    thresh  thresh  prob
            #                                                            (bytes)  (bytes)
            #   0             0/0               0/0               0/0      20000    40000  1/10
            #   1           328/78720          38/9120            0/0      22000    40000  1/10
            #   2             0/0               0/0               0/0      24000    40000  1/10
            #   3             0/0               0/0               0/0      26000    40000  1/10
            #   4             0/0               0/0               0/0      28000    40000  1/10
            m = p27.match(line)
            if m:
                if class_line_type == 1:
                    value1_pkts = "transmitted_packets"
                    value1_bytes = "transmitted_bytes"
                    value2_pkts = "random_drop_packets"
                    value2_bytes = "random_drop_bytes"
                    value3_pkts = "tail_drop_packets"
                    value3_bytes = "tail_drop_bytes"
                    value4 = "minimum_thresh"
                    value5 = "maximum_thresh"
                    value6 = "mark_prob"
                elif class_line_type == 2:
                    value1 = "random_drop"
                    value2 = "tail_drop"
                    value3 = "minimum_thresh"
                    value4 = "maximum_thresh"
                    value5 = "mark_prob"
                    value6 = "output"
                else:
                    continue
                group = m.groupdict()
                class_val = group["class"]
                class_random_dict = random_detect_dict.setdefault(
                    "class", {}
                ).setdefault(class_val, {})
                class_random_dict[value1_pkts] = group["value1_pkts"]
                class_random_dict[value1_bytes] = group["value1_bytes"]
                class_random_dict[value2_pkts] = group["value2_pkts"]
                class_random_dict[value2_bytes] = group["value2_bytes"]
                class_random_dict[value3_pkts] = group["value3_pkts"]
                class_random_dict[value3_bytes] = group["value3_bytes"]
                class_random_dict[value4] = group["value4"]
                class_random_dict[value5] = group["value5"]
                class_random_dict[value6] = group["value6"]
                continue

            # policy wred-policy
            m = p28.match(line)
            if m:
                policy = m.groupdict()["policy"]
                policy_dict = class_dict.setdefault("policy", {}).setdefault(policy, {})
                continue

            # class prec2
            m = p29.match(line)
            if m:
                precedence_list, bytes1_list, bytes2_list, bytes3_list = (
                    [] for _ in range(4)
                )
                class_value = m.groupdict()["class"]
                class_dictionary = policy_dict.setdefault("class", {}).setdefault(
                    class_value, {}
                )
                continue

            # bandwidth 1000
            m = p30.match(line)
            if m:
                class_dictionary["bandwidth"] = int(m.groupdict()["bandwidth"])
                continue

            # bandwidth remaining ratio 1
            m = p31.match(line)
            if m:
                class_dict["bandwidth_remaining_ratio"] = int(
                    m.groupdict()["bandwidth_remaining_ratio"]
                )
                continue

            # bandwidth:class-based wfq, weight 25
            m = p32.match(line)
            if m:
                class_dict["bandwidth"] = m.groupdict()["bandwidth"]
                continue

            # random-detect
            m = p33.match(line)
            if m:
                random_dict = class_dictionary.setdefault("random_detect", {})
                continue

            # random-detect precedence 2 100 bytes 200 bytes 10
            m = p33_1.match(line)
            if m:
                precedence_list.append(int(m.groupdict()["precedence"]))
                bytes1_list.append(int(m.groupdict()["bytes1"]))
                bytes2_list.append(int(m.groupdict()["bytes2"]))
                bytes3_list.append(int(m.groupdict()["bytes3"]))
                random_dict["precedence"] = precedence_list
                random_dict["bytes1"] = bytes1_list
                random_dict["bytes2"] = bytes2_list
                random_dict["bytes3"] = bytes3_list
                continue

            # packet output 90, packet drop 0
            m = p34.match(line)
            if m:
                class_dict["packet_output"] = int(m.groupdict()["packet_output"])
                class_dict["packet_drop"] = int(m.groupdict()["packet_drop"])
                continue

            # tail/random drop 0, no buffer drop 0, other drop 0
            m = p35.match(line)
            if m:
                class_dict["tail_random_drops"] = int(
                    m.groupdict()["tail_random_drops"]
                )
                class_dict["no_buffer_drops"] = int(m.groupdict()["no_buffer_drops"])
                class_dict["other_drops"] = int(m.groupdict()["other_drops"])
                continue

            # queue limit 1966 us/ 49152 bytes
            m = p36.match(line)
            if m:
                if queue_stats == 1:
                    priority_dict["queue_limit_us"] = int(
                        m.groupdict()["queue_limit_us"]
                    )
                    priority_dict["queue_limit_bytes"] = int(
                        m.groupdict()["queue_limit_bytes"]
                    )
                else:
                    class_dict["queue_limit_us"] = int(m.groupdict()["queue_limit_us"])
                    class_dict["queue_limit_bytes"] = int(
                        m.groupdict()["queue_limit_bytes"]
                    )
                continue

            # Priority: 10% (100000 kbps), burst bytes 2500000, b/w exceed drops: 44577300
            m = p37.match(line)
            if m:
                pri_dict = class_dict.setdefault("priority", {})
                pri_dict["percent"] = int(m.groupdict()["percent"])
                pri_dict["kbps"] = int(m.groupdict()["kbps"])
                pri_dict["burst_bytes"] = int(m.groupdict()["burst_bytes"])
                if m.group("exceed_drops"):
                    pri_dict["exceed_drops"] = int(m.groupdict()["exceed_drops"])
                continue

            # Priority Level: 1
            m = p38.match(line)
            if m:
                class_dict["priority_level"] = int(m.groupdict()["priority_level"])
                continue

            # bandwidth remaining 70%
            m = p39.match(line)
            if m:
                class_dict["bandwidth_remaining_percent"] = int(
                    m.groupdict()["bandwidth_remaining_percent"]
                )
                continue

            # Priority: Strict, b/w exceed drops: 0
            m = p40.match(line)
            if m:
                pri_dict = class_dict.setdefault("priority", {})
                pri_dict["type"] = m.groupdict()["type"]
                pri_dict["exceed_drops"] = int(m.groupdict()["exceed_drops"])
                continue

            # Virtual Class   min/max        Transmit                     Random drop                 AFD Weight
            # 0          10 / 20        (Byte)33459183360             27374016                     12
            m = p42.match(line)
            if m:
                afd_wred_dict = class_dict.setdefault("afd_wred_stats", {})
                afc_wred_vc_dict = afd_wred_dict.setdefault(
                    "virtual_class", {}
                ).setdefault(int(m.groupdict()["virtual_class"]), {})
                afc_wred_vc_dict["min"] = int(m.groupdict()["min"])
                afc_wred_vc_dict["max"] = int(m.groupdict()["max"])
                afc_wred_vc_dict["transmit_bytes"] = int(m.groupdict()["tx_bytes"])
                afc_wred_vc_dict["random_drop_bytes"] = int(
                    m.groupdict()["random_drop_bytes"]
                )
                afc_wred_vc_dict["afd_weight"] = int(m.groupdict()["afd_weight"])
                continue

            # (Pkts)68692637637             0
            m = p43.match(line)
            if m:
                afc_wred_vc_dict["transmit_packets"] = int(m.groupdict()["tx_packets"])
                afc_wred_vc_dict["random_drop_packets"] = int(
                    m.groupdict()["random_drop_packets"]
                )
                continue

            # dscp : 1
            m = p44.match(line)
            if m:
                afc_wred_vc_dict["dscp"] = int(m.groupdict()["dscp"])
                continue

            # Total Drops(Bytes)   : 0
            m = p45.match(line)
            if m:
                afd_wred_dict["total_drops_bytes"] = int(
                    m.groupdict()["total_drops_bytes"]
                )
                continue

            # Total Drops(Packets) : 0
            m = p46.match(line)
            if m:
                afd_wred_dict["total_drops_packets"] = int(
                    m.groupdict()["total_drops_packets"]
                )
                continue

            # (total drops) 0
            m = p47.match(line)
            if m:
                if queue_stats == 1:
                    priority_dict["total_drops"] = int(m.groupdict()["total_drops"])
                else:
                    class_dict["total_drops"] = int(m.groupdict()["total_drops"])
                continue

            # (bytes output) 0
            m = p48.match(line)
            if m:
                if queue_stats == 1:
                    priority_dict["bytes_output"] = int(m.groupdict()["bytes_output"])
                else:
                    class_dict["bytes_output"] = int(m.groupdict()["bytes_output"])
                continue

            # Overhead Accounting Enabled
            m = p49.match(line)
            if m:
                class_dict["overhead_accounting"] = m.groupdict()["enabled"]

            # Fair-queue: per-flow queue limit 128 packets
            m = p50.match(line)
            if m:
                class_dict["fair_queue_limit_per_flow"] = int(
                    m.groupdict()["queue_limit"]
                )

        return ret_dict


# ===========================================
# Parser for:
#   * 'show policy-map interface {interface} service instance {service_instance}'
# ===========================================
class ShowPolicyMapInterfaceServiceInstance(
    ShowPolicyMapTypeSuperParser, ShowPolicyMapTypeSchema
):
    """Parser for:
    * 'show policy-map interface {interface} service instance {service_instance}'
    """

    cli_command = [
        "show policy-map interface {interface} service instance {service_instance}"
    ]

    def cli(self, interface, service_instance, output=None):

        if output is None:
            cmd = self.cli_command[0].format(
                interface=interface, service_instance=service_instance
            )
            show_output = self.device.execute(cmd)
        else:
            show_output = output

        # Call super
        return super().cli(output=show_output)


# =====================================================================
# Parser for:
#   * 'show policy-map interface {interface} service instance {service_instance} input'
# =====================================================================
class ShowPolicyMapInterfaceServiceInstanceInput(
    ShowPolicyMapTypeSuperParser, ShowPolicyMapTypeSchema
):
    """Parser for:
    * 'show policy-map interface {interface} service instance {service_instance} input'
    """

    cli_command = [
        "show policy-map interface {interface} service instance {service_instance} input"
    ]

    def cli(self, interface, service_instance, output=None):

        if output is None:
            cmd = self.cli_command[0].format(
                interface=interface, service_instance=service_instance
            )
            show_output = self.device.execute(cmd)
        else:
            show_output = output

        # Call super
        return super().cli(
            output=show_output, interface=interface, service_instance=service_instance
        )


# =====================================================================
# Parser for:
#   * 'show policy-map interface {interface} service instance {service_instance} output'
# =====================================================================
class ShowPolicyMapInterfaceServiceInstanceOutput(
    ShowPolicyMapTypeSuperParser, ShowPolicyMapTypeSchema
):
    """Parser for:
    * 'show policy-map interface {interface} service instance {service_instance} output'
    """

    cli_command = [
        "show policy-map interface {interface} service instance {service_instance} output"
    ]

    def cli(self, interface, service_instance, output=None):

        if output is None:
            cmd = self.cli_command[0].format(
                interface=interface, service_instance=service_instance
            )
            # Execute command
            show_output = self.device.execute(cmd)
        else:
            show_output = output

        # Call super
        return super().cli(
            output=show_output, interface=interface, service_instance=service_instance
        )
