# PIPELINE_V2 Feature Codebook

This codebook documents V2 feature columns and how they are measured/generated.

Scope:

- Parser packet rows: packet-level fields consumed by flow generation.
- Generator flow rows: identity and per-flow features.
- Enricher flow rows: across-flow contextual features.
- Labeling rows: per-flow ground-truth targets and episode provenance metadata.

## 0 - Conditional Value Conventions (Important)

These conventions explain when a numeric `0` is a real measured value versus a structural fallback.

### 0.1 Parser conventions (packet rows)

- Protocol-inapplicable fields are zero-filled only after successful L4 parse.
- For successfully parsed TCP rows: TCP fields are parsed values, UDP-specific fields are `0`.
- For successfully parsed UDP rows: UDP fields are parsed values, TCP-specific fields are `0`.
- If `inner_ip_proto` indicates TCP/UDP but the minimum L4 header cannot be parsed, L4-specific fields remain unavailable (`None`/blank) rather than forced to `0`.
- INT fields remain unavailable (`None`/blank) when INT telemetry is not present/parseable.

### 0.2 Generator conventions (flow rows)

- `pkts_total` and `bytes_total` are exact directional sums.
- `duration` is exported as observed (`flow_end_time - flow_start_time`).
- Rate fields use explicit zero-duration handling: duration `== 0` gives rate `0.0`; valid positive duration uses normal division.
- `iat_int_count` is the semantic indicator for INT-IAT availability:
  - `iat_int_count == 0`: no measurable INT-IAT observations, exported INT-IAT stats are numeric `0.0`.
  - `iat_int_count == 1`: mean/min/max are that single value, std is `0.0`.

### 0.3 Enricher conventions (context rows)

- Forward context is always computed from forward contribution (`pkts_fwd > 0`).
- Backward context is computed from aggregate tables only when `pkts_bwd > 0`.
- When `pkts_bwd == 0`, all `bwd_*` enrichment fields are explicitly written as `0` (ML-ready no-backward-context encoding).
- This zero-fill is scoped only to the no-backward-contribution case; it is not a global missing-value replacement rule.

## 1 - Packet-Level Features (Parser Output)

These are packet-row columns used as direct inputs to flow generation.

| Feature                           | Stage  | How measured/generated                                                                                                                                                             |
| --------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packet_uid`                      | parser | Stable packet identity string from timeframe/file/index.                                                                                                                           |
| `source_file`                     | parser | Source CSV/PCAP provenance for each packet.                                                                                                                                        |
| `packet_index`                    | parser | Packet order index within source file.                                                                                                                                             |
| `packet_time`                     | parser | Packet timestamp from PCAP metadata (seconds).                                                                                                                                     |
| `timeframe_id`                    | parser | Timeframe identifier from filename/range naming.                                                                                                                                   |
| `direction`                       | parser | Path/inference label (`fwd`, `bwd`, `all`, `unknown`).                                                                                                                             |
| `inner_ip_src`                    | parser | Wrapped inner IPv4 source address.                                                                                                                                                 |
| `inner_ip_dst`                    | parser | Wrapped inner IPv4 destination address.                                                                                                                                            |
| `inner_ip_proto`                  | parser | Inner IP protocol numeric value (for fallback protocol inference).                                                                                                                 |
| `l4_proto`                        | parser | Parsed L4 protocol label (`TCP`, `UDP`, or empty if unavailable).                                                                                                                  |
| `src_port`                        | parser | L4 source port from inner packet.                                                                                                                                                  |
| `dst_port`                        | parser | L4 destination port from inner packet.                                                                                                                                             |
| `tcp_dataofs`                     | parser | TCP data-offset nibble from header (declared header size indicator). Exported value is declaration, not proof all declared TCP header bytes are captured in this collector layout. |
| `tcp_header_len_bytes`            | parser | `tcp_dataofs * 4` declared TCP header length in bytes.                                                                                                                             |
| `tcp_options_len`                 | parser | `max(tcp_header_len_bytes - 20, 0)` declared TCP options length.                                                                                                                   |
| `inner_ip_len`                    | parser | Declared inner IPv4 total length (bytes).                                                                                                                                          |
| `inner_ip_total_length_declared`  | parser | Redundant declared IP total length (bytes), fallback for size extraction.                                                                                                          |
| `int_ingress_timestamp`           | parser | INT ingress timestamp (nanosecond counter domain).                                                                                                                                 |
| `int_egress_timestamp`            | parser | INT egress timestamp (nanosecond counter domain).                                                                                                                                  |
| `int_queue_occupancy`             | parser | INT queue occupancy at hop.                                                                                                                                                        |
| `inner_ip_truncated_vs_declared`  | parser | Boolean indicator that captured bytes differ from declared inner IP length.                                                                                                        |
| `inner_udp_truncated_vs_declared` | parser | Boolean indicator that captured UDP bytes differ from declared UDP length.                                                                                                         |
| `tcp_flag_syn`                    | parser | TCP SYN flag indicator.                                                                                                                                                            |
| `tcp_flag_ack`                    | parser | TCP ACK flag indicator.                                                                                                                                                            |
| `tcp_flag_fin`                    | parser | TCP FIN flag indicator.                                                                                                                                                            |
| `tcp_flag_rst`                    | parser | TCP RST flag indicator.                                                                                                                                                            |
| `tcp_flag_psh`                    | parser | TCP PSH flag indicator.                                                                                                                                                            |
| `tcp_flag_urg`                    | parser | TCP URG flag indicator.                                                                                                                                                            |
| `capture_start_utc`               | parser | Capture-window start time for timestamp-range named files.                                                                                                                         |
| `capture_end_utc`                 | parser | Capture-window end time for timestamp-range named files.                                                                                                                           |
| `capture_start_epoch`             | parser | Capture-window start epoch seconds.                                                                                                                                                |
| `capture_end_epoch`               | parser | Capture-window end epoch seconds.                                                                                                                                                  |

## 2 - Identity Features (Generator Output)

These define flow identity, segmenting, orientation, and provenance.

| Feature                    | Category    | How measured/generated                                                                                                                           |
| -------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `base_flow_key`            | identity    | Direction-independent canonical identity: \`proto                                                                                                |
| `flow_id`                  | identity    | Segment identifier: \`base_flow_key                                                                                                              |
| `flow_segment_id`          | identity    | Incrementing segment counter per `base_flow_key` in `flow_segments` table.                                                                       |
| `timeframe_id`             | identity    | First packet timeframe value for the active segment key context (currently same value as `first_timeframe_id` in canonical export).              |
| `proto`                    | identity    | Normalized protocol number (for example TCP=6, UDP=17).                                                                                          |
| `ip_a`                     | orientation | Segment orientation endpoint A (source of first observed packet in segment).                                                                     |
| `ip_b`                     | orientation | Segment orientation endpoint B (destination of first observed packet in segment).                                                                |
| `port_a`                   | orientation | Port paired with `ip_a`.                                                                                                                         |
| `port_b`                   | orientation | Port paired with `ip_b`.                                                                                                                         |
| `first_packet_direction`   | orientation | Direction of the first packet relative to exported orientation (currently `fwd` in canonical export because A/B are set from that first packet). |
| `first_observed_src_ip`    | orientation | Source IP from the segment's first packet (currently matches `ip_a` in canonical export).                                                        |
| `first_observed_dst_ip`    | orientation | Destination IP from the segment's first packet (currently matches `ip_b` in canonical export).                                                   |
| `first_observed_src_port`  | orientation | Source port from the segment's first packet (currently matches `port_a` in canonical export).                                                    |
| `first_observed_dst_port`  | orientation | Destination port from the segment's first packet (currently matches `port_b` in canonical export).                                               |
| `first_packet_syn`         | orientation | Whether first packet had SYN set.                                                                                                                |
| `first_packet_ack`         | orientation | Whether first packet had ACK set.                                                                                                                |
| `first_packet_was_syn`     | orientation | Derived: TCP and first packet SYN=1 and ACK=0.                                                                                                   |
| `first_packet_was_syn_ack` | orientation | Derived: TCP and first packet SYN=1 and ACK=1.                                                                                                   |
| `flow_initiator`           | orientation | Role label derived from first-packet semantics (currently constant `observed_first_packet_src` in canonical export).                             |
| `initiator_confidence`     | orientation | Confidence tag (`tcp_syn_noack_observed`, `observed_first_packet`, `unknown`).                                                                   |
| `first_source_file`        | provenance  | First source file seen by the segment.                                                                                                           |
| `last_source_file`         | provenance  | Most recent source file seen by the segment.                                                                                                     |
| `source_file_count`        | provenance  | Count of distinct source-file transitions observed while segment stayed active.                                                                  |
| `first_timeframe_id`       | provenance  | First timeframe observed for the segment.                                                                                                        |
| `last_timeframe_id`        | provenance  | Last timeframe observed for the segment.                                                                                                         |
| `crosses_file_boundary`    | provenance  | 1 if the segment consumed packets from more than one source file.                                                                                |
| `flow_start_time`          | lifecycle   | Export alias of segment `first_time` (seconds).                                                                                                  |
| `flow_end_time`            | lifecycle   | Export alias of segment `last_time` (seconds).                                                                                                   |
| `termination_reason`       | lifecycle   | Segment close reason (`inactive_timeout`, `active_timeout`, `tcp_rst`, `tcp_fin_both`, `end_of_input`).                                          |

Current canonical-export note: some identity/orientation columns are intentionally redundant for traceability (`timeframe_id` with `first_timeframe_id`, and first-observed endpoint columns with `ip_a/ip_b/port_a/port_b`).

## 3 - Flow-Level Features (Generator Output)

These are per-segment packet/byte/time/statistical features.

### 3.1 Directional and total counts

| Feature       | How measured/generated                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `pkts_fwd`    | Count of packets matching exported forward direction (`ip_a:port_a -> ip_b:port_b`).                    |
| `pkts_bwd`    | Count of packets matching exported backward direction.                                                  |
| `bytes_fwd`   | Sum of packet sizes (`inner_ip_len` fallback to `inner_ip_total_length_declared`) over forward packets. |
| `bytes_bwd`   | Same as above for backward packets.                                                                     |
| `pkts_total`  | `pkts_fwd + pkts_bwd`.                                                                                  |
| `bytes_total` | `bytes_fwd + bytes_bwd`.                                                                                |
| `duration`    | `last_time - first_time` for the segment.                                                               |

Condition note: `pkts_total` and `bytes_total` are exact sums (not separately estimated), and `duration` is exported as observed even when it is `0`.

### 3.2 Rate features

The duration field is kept as-is. For rate features, the policy is:

- if `duration > 0`, compute normally;
- if `duration == 0`, export the rate fields as `0.0`;
- if `duration` is missing or negative, leave the rate field empty (`None`/blank).

There is no 1-second clamp: sub-second flows are computed at their true duration.

| Feature     | How measured/generated                                                                                         |
| ----------- | -------------------------------------------------------------------------------------------------------------- |
| `fwd_pps`   | If `duration > 0`, `pkts_fwd / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank.    |
| `bwd_pps`   | If `duration > 0`, `pkts_bwd / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank.    |
| `total_pps` | If `duration > 0`, `pkts_total / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank.  |
| `fwd_Bps`   | If `duration > 0`, `bytes_fwd / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank.   |
| `bwd_Bps`   | If `duration > 0`, `bytes_bwd / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank.   |
| `total_Bps` | If `duration > 0`, `bytes_total / duration`; if `duration == 0`, `0.0`; if `duration` missing/negative, blank. |

### 3.3 Packet-size statistics

| Feature         | How measured/generated                                                                                               |
| --------------- | -------------------------------------------------------------------------------------------------------------------- |
| `mean_pkt_size` | `pkt_size_sum / pkts_total` when `pkts_total > 0`, otherwise blank.                                                  |
| `pkt_size_std`  | Std dev from `pkt_size_sum_sq/pkts_total - mean^2` when `pkts_total > 0`, variance clamped at zero, otherwise blank. |
| `pkt_size_min`  | Minimum observed packet size in segment, blank if no packets.                                                        |
| `pkt_size_max`  | Maximum observed packet size in segment, blank if no packets.                                                        |

### 3.4 Hop, INT-IAT, latency, queue features

| Feature                | How measured/generated                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `mean_hop_count`       | `hop_count_sum / hop_count_count` when `hop_count_count > 0`, otherwise blank.                                                             |
| `mean_hop_latency`     | `latency_sum / hop_count_count` when `hop_count_count > 0`, otherwise blank.                                                               |
| `iat_int_count`        | Number of actual INT-domain IAT observations in the flow. This is the semantic count; it stays at `0` when there is no measurable INT IAT. |
| `mean_iat_int_ns`      | Mean of INT-domain inter-arrival deltas (egress-first fallback logic, wrap-aware). If `iat_int_count == 0`, this is reported as `0.0`.     |
| `iat_std_int_ns`       | Std dev of INT IAT values. If `iat_int_count <= 1`, this is reported as `0.0`.                                                             |
| `iat_min_int_ns`       | Minimum INT IAT value in segment. If `iat_int_count == 0`, this is reported as `0.0`.                                                      |
| `iat_max_int_ns`       | Maximum INT IAT value in segment. If `iat_int_count == 0`, this is reported as `0.0`.                                                      |
| `latency_min`          | Minimum per-packet INT latency aggregate over packets with latency observations, otherwise blank.                                          |
| `latency_max`          | Maximum per-packet INT latency aggregate over packets with latency observations, otherwise blank.                                          |
| `latency_std`          | Std dev of per-packet latency aggregates when `hop_count_count > 0` (variance clamped at zero), otherwise blank.                           |
| `queue_occupancy_mean` | Mean of queue occupancy observations when `queue_occupancy_count > 0`, otherwise blank.                                                    |
| `queue_occupancy_std`  | Std dev of queue occupancy when `queue_occupancy_count > 0` (variance clamped at zero), otherwise blank.                                   |
| `queue_occupancy_max`  | Maximum observed queue occupancy, blank if no queue observations were captured.                                                            |

For INT IAT statistics, the semantic convention is:

- `iat_int_count = 0` means there were no measurable INT IAT observations.
- In that case, the stat fields are reported as numeric zeroes (`0.0`) rather than nulls, so downstream consumers can still treat them as valid numeric values.
- For `iat_int_count = 1`, the mean, min, and max equal the single observed IAT value, while std is `0.0`.
- For `iat_int_count >= 2`, values are computed normally.

### 3.5 TCP flag counts, ratios, and fractions

For each flag in `{syn, ack, fin, rst, psh, urg}` these five columns exist:

- `<flag>_count_fwd`
- `<flag>_count_bwd`
- `<flag>_ratio_fwd` = `<flag>_count_fwd / pkts_fwd` (0 when `pkts_fwd=0`)
- `<flag>_ratio_bwd` = `<flag>_count_bwd / pkts_bwd` (0 when `pkts_bwd=0`)
- `<flag>_fraction` = `(<flag>_count_fwd + <flag>_count_bwd) / pkts_total` (0 when `pkts_total=0`)

Condition note: ratios/fractions are bounded in `[0,1]` by construction, and denominator-zero cases are represented as numeric `0.0`.

### 3.6 Directionality and share features

| Feature             | How measured/generated                                     |
| ------------------- | ---------------------------------------------------------- |
| `bytes_per_pkt_fwd` | `bytes_fwd / pkts_fwd` if `pkts_fwd > 0`, else `0.0`.      |
| `bytes_per_pkt_bwd` | `bytes_bwd / pkts_bwd` if `pkts_bwd > 0`, else `0.0`.      |
| `bytes_per_pkt_gap` | `bytes_per_pkt_fwd - bytes_per_pkt_bwd` (always computed). |
| `fwd_share_pkts`    | `pkts_fwd / pkts_total` (empty when `pkts_total=0`).       |
| `fwd_share_bytes`   | `bytes_fwd / bytes_total` (empty when `bytes_total=0`).    |

Condition note: unlike flag ratios, `fwd_share_pkts` and `fwd_share_bytes` are left blank when their denominator is zero.

### 3.7 Additional quality and imbalance features

| Feature                    | How measured/generated                                                                                                            |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `small_pkt_fraction_total` | If `pkts_total > 0`, `(small_pkt_count_fwd + small_pkt_count_bwd) / pkts_total` where small means `pkt_bytes <= 100`; else `0.0`. |
| `tiny_pkt_fraction_total`  | If `pkts_total > 0`, `(tiny_pkt_count_fwd + tiny_pkt_count_bwd) / pkts_total` where tiny means `pkt_bytes <= 40`; else `0.0`.     |
| `syn_ack_gap`              | `syn_count_fwd - ack_count_bwd`.                                                                                                  |
| `truncated_ip_fraction`    | If `pkts_total > 0`, `truncated_ip_count / pkts_total`; else blank.                                                               |
| `truncated_udp_fraction`   | If `pkts_total > 0`, `truncated_udp_count / pkts_total`; else blank.                                                              |

## 4 - Across-Flow Contextual Features (Enricher Output)

The enricher keeps all generator columns and appends contextual aggregates.

Counting model:

- Forward contribution exists only if `pkts_fwd > 0` with src=`ip_a:port_a`, dst=`ip_b:port_b`, bytes=`bytes_fwd`.
- Backward contribution exists only if `pkts_bwd > 0` with src=`ip_b:port_b`, dst=`ip_a:port_a`, bytes=`bytes_bwd`.
- When no backward contribution exists (`pkts_bwd == 0`), all backward contextual fields are written as numeric `0`.

Condition note: backward enrichment zeros mean not-applicable-no-backward-traffic, while positive-backward rows are computed from actual aggregate-table lookups.

### 4.1 Forward destination context (`fwd_dst_*`)

| Feature                            |
| ---------------------------------- |
| `fwd_dst_flow_count`               |
| `fwd_dst_unique_src_ips`           |
| `fwd_dst_unique_src_ports`         |
| `fwd_dst_unique_dst_ports`         |
| `fwd_dst_pkts_total`               |
| `fwd_dst_bytes_total`              |
| `fwd_dst_service_flow_count`       |
| `fwd_dst_service_unique_src_ips`   |
| `fwd_dst_service_unique_src_ports` |
| `fwd_dst_service_pkts_total`       |
| `fwd_dst_service_bytes_total`      |
| `fwd_flow_share_of_dst_pkts`       |
| `fwd_flow_share_of_dst_bytes`      |

Generation summary:

- Destination universe key: `(timeframe_id, proto, dst_ip = ip_b)`.
- Service key adds `dst_port = port_b`.
- Shares use this flow's forward numerator over matching forward aggregate denominator.

### 4.2 Backward destination context (`bwd_dst_*`)

| Feature                            |
| ---------------------------------- |
| `bwd_dst_flow_count`               |
| `bwd_dst_unique_src_ips`           |
| `bwd_dst_unique_src_ports`         |
| `bwd_dst_unique_dst_ports`         |
| `bwd_dst_pkts_total`               |
| `bwd_dst_bytes_total`              |
| `bwd_dst_service_flow_count`       |
| `bwd_dst_service_unique_src_ips`   |
| `bwd_dst_service_unique_src_ports` |
| `bwd_dst_service_pkts_total`       |
| `bwd_dst_service_bytes_total`      |
| `bwd_flow_share_of_dst_pkts`       |
| `bwd_flow_share_of_dst_bytes`      |

Generation summary:

- Destination universe key: `(timeframe_id, proto, dst_ip = ip_a)` from backward direction view.
- Service key adds `dst_port = port_a`.
- Shares use this flow's backward numerator over matching backward aggregate denominator.

### 4.3 Forward source context (`fwd_src_*`)

| Feature                    |
| -------------------------- |
| `fwd_src_flow_count`       |
| `fwd_src_unique_dst_ips`   |
| `fwd_src_unique_dst_ports` |
| `fwd_src_unique_src_ports` |
| `fwd_src_pkts_total`       |
| `fwd_src_bytes_total`      |

Generation summary:

- Source universe key: `(timeframe_id, proto, src_ip = ip_a)` under forward contribution.

### 4.4 Backward source context (`bwd_src_*`)

| Feature                    |
| -------------------------- |
| `bwd_src_flow_count`       |
| `bwd_src_unique_dst_ips`   |
| `bwd_src_unique_dst_ports` |
| `bwd_src_unique_src_ports` |
| `bwd_src_pkts_total`       |
| `bwd_src_bytes_total`      |

Generation summary:

- Source universe key: `(timeframe_id, proto, src_ip = ip_b)` under backward contribution.

## 5 - Labeling / Ground-Truth Columns

These are added during labeling (downstream of parser/generator/enricher) and represent per-flow targets plus episode provenance.

| Feature             | How measured/generated                                                                                                                                                                         |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `label`             | Binary per-flow ground-truth target: `1` when the flow satisfies episode-specific attack attribution rules, and `0` for all other flows captured during that same episode (background/normal). |
| `class_label`       | Specific per-flow class: for `label=1` use episode `attack_type`; for `label=0` set to `normal`.                                                                                               |
| `broad_label`       | Broad per-flow class: for `label=1` use episode family from `BROAD_CATEGORY`; for `label=0` set to `normal`.                                                                                   |
| `episode_name`      | Simulation/capture episode during which the flow was observed; the episode may be an attack episode even when the individual flow label is `0` (normal/background).                            |
| `episode_start_utc` | Configured UTC start time for that episode (metadata).                                                                                                                                         |
| `episode_end_utc`   | Configured UTC end time for that episode (metadata).                                                                                                                                           |

Labeling logic note: a flow can come from an attack episode but still be labeled normal (`label=0`, `class_label=normal`, `broad_label=normal`) because labels are assigned per flow, not per episode.

Redundancy note: the labeling output intentionally omits per-row `episode_id`, `attack_type`, and `broad_category` because those are recoverable/redundant with `episode_name`, `class_label`, and `broad_label`.

## 6 - Exhaustive Generator Feature Name List (Export Order)

This is the exact generator CSV header set before enricher appends contextual fields.

`base_flow_key, flow_id, flow_segment_id, timeframe_id, proto, ip_a, ip_b, port_a, port_b, first_observed_src_ip, first_observed_dst_ip, first_observed_src_port, first_observed_dst_port, first_packet_syn, first_packet_ack, first_packet_was_syn, first_packet_was_syn_ack, first_packet_direction, flow_initiator, initiator_confidence, pkts_fwd, pkts_bwd, bytes_fwd, bytes_bwd, pkts_total, bytes_total, duration, flow_start_time, flow_end_time, termination_reason, first_source_file, last_source_file, source_file_count, first_timeframe_id, last_timeframe_id, crosses_file_boundary, fwd_pps, bwd_pps, total_pps, total_Bps, fwd_Bps, bwd_Bps, mean_pkt_size, pkt_size_std, pkt_size_min, pkt_size_max, mean_hop_count, mean_hop_latency, iat_int_count, mean_iat_int_ns, iat_std_int_ns, iat_min_int_ns, iat_max_int_ns, latency_min, latency_max, latency_std, syn_count_fwd, syn_count_bwd, syn_ratio_fwd, syn_ratio_bwd, syn_fraction, ack_count_fwd, ack_count_bwd, ack_ratio_fwd, ack_ratio_bwd, ack_fraction, fin_count_fwd, fin_count_bwd, fin_ratio_fwd, fin_ratio_bwd, fin_fraction, rst_count_fwd, rst_count_bwd, rst_ratio_fwd, rst_ratio_bwd, rst_fraction, psh_count_fwd, psh_count_bwd, psh_ratio_fwd, psh_ratio_bwd, psh_fraction, urg_count_fwd, urg_count_bwd, urg_ratio_fwd, urg_ratio_bwd, urg_fraction, bytes_per_pkt_fwd, bytes_per_pkt_bwd, bytes_per_pkt_gap, small_pkt_fraction_total, tiny_pkt_fraction_total, syn_ack_gap, fwd_share_pkts, fwd_share_bytes, queue_occupancy_mean, queue_occupancy_std, queue_occupancy_max, truncated_ip_fraction, truncated_udp_fraction`
