-- Wireshark Lua dissector for INT telemetry reports.
-- Updated to parse INT hop metadata with explicit hop boundaries and
-- bounds checks, matching the behavior of the companion Python parser.

-- Protocols
p_telemetryproto = Proto("telemetry", "Telemetry Header")
p_modproto = Proto("mod", "Mirror-On-Drop")
p_swlocalproto = Proto("switch_local", "Switch Local")
p_intshimproto = Proto("int_shim", "INT Shim")
p_intmetadataproto = Proto("int_metadata", "INT Metadata")
p_intstackproto = Proto("int_stack", "INT Metadata Stack")

-- Constants
local TELEMETRY_REPORT_LEN = 16
local INT_SHIM_LEN = 4
local INT_MD_LEN = 8
local ETH_LEN = 14
local VLAN_LEN = 4
local IPV4_MIN_LEN = 20
local TCP_FIXED_LEN = 20
local UDP_LEN = 8

-- Report Header
local f_report_header = ProtoField.none("telemetry.f_report_header", "Telemetry Report Header", base.HEX)
local f_version = ProtoField.uint8("telemetry.f_report_header.f_version", "Version", base.HEX)
local f_length = ProtoField.uint8("telemetry.f_report_header.f_length", "Length", base.DEC)
local f_next_proto = ProtoField.uint8("telemetry.f_report_header.f_next_proto", "Protocol Number", base.HEX)
local f_rep_m_bits = ProtoField.uint8("telemetry.f_report_header.f_rep_m_bits", "RepMdBits", base.HEX)
local f_rsvd_1 = ProtoField.uint8("telemetry.f_report_header.f_rsvd_1", "Reserved 1", base.HEX)
local f_drop = ProtoField.bool("telemetry.f_report_header.f_drop", "Drop Bit", base.NONE)
local f_queue = ProtoField.bool("telemetry.f_report_header.f_queue", "Queue Bit", base.NONE)
local f_flow = ProtoField.bool("telemetry.f_report_header.f_flow", "Flow Bit", base.NONE)
local f_rsvd_2 = ProtoField.uint16("telemetry.f_report_header.f_rsvd_2", "Reserved 2", base.HEX)
local f_hw_id = ProtoField.uint8("telemetry.f_report_header.f_hw_id", "Hardware ID", base.HEX)
local f_switch_id = ProtoField.uint32("telemetry.f_report_header.f_switch_id", "Switch ID", base.HEX)
local f_seq_num = ProtoField.uint32("telemetry.f_report_header.f_seq_num", "Sequence Number", base.HEX)
local f_ingress_ts = ProtoField.uint32("telemetry.f_report_header.f_ingress_ts", "Ingress Timestamp", base.DEC)

-- INT Shim Header
local shim_header = ProtoField.none("int_shim.shim_header", "INT Shim Header", base.HEX)
local shim_type = ProtoField.uint8("int_shim.shim_header.shim_type", "Type", base.HEX)
local shim_rsvd1 = ProtoField.uint8("int_shim.shim_header.shim_rsvd1", "Reserved 1", base.HEX)
local shim_len = ProtoField.uint8("int_shim.shim_header.shim_len", "Length", base.DEC)
local shim_dscp = ProtoField.uint8("int_shim.shim_header.shim_dscp", "DSCP", base.HEX)
local shim_rsvd2 = ProtoField.uint8("int_shim.shim_header.shim_rsvd2", "Reserved 2", base.HEX)

-- INT Metadata Header
local int_metadata_header = ProtoField.none("int_metadata.int_metadata_header", "INT Metadata Header", base.HEX)
local int_version = ProtoField.uint8("int_metadata.int_metadata_header.int_version", "Version", base.DEC)
local int_replication = ProtoField.uint8("int_metadata.int_metadata_header.int_replication", "Replication Requested", base.DEC)
local int_copy = ProtoField.bool("int_metadata.int_metadata_header.copy", "Copy Bit", base.NONE)
local int_exceeded = ProtoField.bool("int_metadata.int_metadata_header.int_exceeded", "Max Hop Count Exceeded", base.NONE)
local int_m = ProtoField.bool("int_metadata.int_metadata_header.int_m", "MTU Exceeded", base.NONE)
local int_rsvd_1 = ProtoField.uint16("int_metadata.int_metadata_header.int_rsvd_1", "Reserved", base.HEX)
local int_hop_ml = ProtoField.uint8("int_metadata.int_metadata_header.int_ml", "Hop ML", base.DEC)
local int_remaining_hop_cnt = ProtoField.uint8("int_metadata.int_metadata_header.int_remaining_hop_cnt", "Remaining Hop Count", base.DEC)
local instruction_bit_0 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_0", "Switch ID Bit", base.NONE)
local instruction_bit_1 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_1", "Ingress + Egress Port ID Bit", base.NONE)
local instruction_bit_2 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_2", "Hop Latency Bit", base.NONE)
local instruction_bit_3 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_3", "Queue ID + Occupancy Bit", base.NONE)
local instruction_bit_4 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_4", "Ingress Timestamp", base.NONE)
local instruction_bit_5 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_5", "Egress Timestamp", base.NONE)
local instruction_bit_6 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_6", "Queue ID + Congestion Status", base.NONE)
local instruction_bit_7 = ProtoField.bool("int_metadata.int_metadata_header.instruction_bit_7", "Egress Port Tx Utilization", base.NONE)
local int_rsvd_instructions = ProtoField.uint8("int_metadata.int_metadata_header.int_rsvd_instructions", "Reserved Instruction bits", base.HEX)
local int_rsvd_2 = ProtoField.uint16("int_metadata.int_metadata_header.int_rsvd_2", "Reserved Bits 2", base.HEX)

-- INT Stack
local int_switch_id = ProtoField.uint32("int_stack.int_switch_id", "Switch ID", base.HEX)
local int_ingress_port = ProtoField.uint16("int_stack.int_ingress_egress_ports.int_ingress_port", "Ingress Port ID", base.DEC)
local int_egress_port = ProtoField.uint16("int_stack.int_ingress_egress_ports.int_egress_port", "Egress Port ID", base.DEC)
local int_hop_latency = ProtoField.uint32("int_stack.int_hop_latency", "Hop Latency", base.DEC)
local int_queue_id = ProtoField.uint8("int_stack.int_queue_id_and_occ.int_queue_id", "Queue ID", base.DEC)
local int_queue_occ = ProtoField.uint32("int_stack.int_queue_id_and_occ.int_queue_occ", "Queue Occupancy", base.DEC)
local int_ingress_ts = ProtoField.uint32("int_stack.int_ingress_ts", "Ingress Timestamp", base.DEC)
local int_egress_ts = ProtoField.uint32("int_stack.int_egress_ts", "Egress Timestamp", base.DEC)

-- Register protocol fields
p_telemetryproto.fields = {
  f_report_header,
  f_version,
  f_length,
  f_next_proto,
  f_rep_m_bits,
  f_rsvd_1,
  f_drop,
  f_queue,
  f_flow,
  f_rsvd_2,
  f_hw_id,
  f_switch_id,
  f_seq_num,
  f_ingress_ts
}

p_intshimproto.fields = {
  shim_header,
  shim_type,
  shim_rsvd1,
  shim_len,
  shim_dscp,
  shim_rsvd2
}

p_intmetadataproto.fields = {
  int_metadata_header,
  int_version,
  int_replication,
  int_copy,
  int_exceeded,
  int_m,
  int_rsvd_1,
  int_hop_ml,
  int_remaining_hop_cnt,
  instruction_bit_0,
  instruction_bit_1,
  instruction_bit_2,
  instruction_bit_3,
  instruction_bit_4,
  instruction_bit_5,
  instruction_bit_6,
  instruction_bit_7,
  int_rsvd_instructions,
  int_rsvd_2
}

p_intstackproto.fields = {
  int_switch_id,
  int_ingress_port,
  int_egress_port,
  int_hop_latency,
  int_queue_id,
  int_queue_occ,
  int_ingress_ts,
  int_egress_ts
}

-- Heuristic helper retained from the original script.
function heur_int_shim(tvbuf, pinfo, tree)
  if tvbuf:len() < 1 then
    return false
  end

  local shim_type_value = tvbuf(0, 1):uint()
  if shim_type_value == 1 or shim_type_value == 2 then
    p_intshimproto.dissector(tvbuf, pinfo, tree)
    return true
  end

  return false
end

-- INT Shim + Metadata + Stack dissector
function p_intshimproto.dissector(tvbuf, pktinfo, root)
  -- Need 4-byte shim + 8-byte metadata header.
  if tvbuf:len() < (INT_SHIM_LEN + INT_MD_LEN) then
    return
  end

  -- INT Shim Header
  local shim_hdr = root:add(p_intshimproto, tvbuf(0, INT_SHIM_LEN))
  shim_hdr:add(shim_header, tvbuf(0, INT_SHIM_LEN))
  shim_hdr:add(shim_type, tvbuf(0, 1))
  shim_hdr:add(shim_rsvd1, tvbuf(1, 1))
  shim_hdr:add(shim_len, tvbuf(2, 1))
  shim_hdr:add(shim_dscp, tvbuf(3, 1):bitfield(0, 6))
  shim_hdr:add(shim_rsvd2, tvbuf(3, 1):bitfield(6, 2))

  -- INT shim length is in 4-byte words and includes:
  --   4-byte shim + 8-byte metadata header + metadata stack.
  local shim_len_words = tvbuf(2, 1):uint()
  if shim_len_words < 3 then
    return
  end

  local int_data_len = (shim_len_words - 3) * 4

  -- INT Metadata Header
  local metadata_tvbuf = tvbuf(INT_SHIM_LEN):tvb()
  if metadata_tvbuf:len() < INT_MD_LEN then
    return
  end

  local metadata_header = root:add(
    p_intmetadataproto,
    metadata_tvbuf(0, INT_MD_LEN)
  )
  metadata_header:add(int_metadata_header, metadata_tvbuf(0, INT_MD_LEN))

  metadata_header:add(int_version, metadata_tvbuf(0, 1):bitfield(0, 4))
  metadata_header:add(int_replication, metadata_tvbuf(0, 1):bitfield(4, 2))
  metadata_header:add(int_copy, metadata_tvbuf(0, 1):bitfield(6, 1))
  metadata_header:add(int_exceeded, metadata_tvbuf(0, 1):bitfield(7, 1))
  metadata_header:add(int_m, metadata_tvbuf(1, 1):bitfield(0, 1))
  metadata_header:add(int_rsvd_1, metadata_tvbuf(1, 2):bitfield(1, 9))

  -- Hop ML is the low 5 bits of byte 2. Wireshark bitfield offsets are
  -- MSB-first, so bitfield(3, 5) selects those low 5 bits.
  local hop_ml_words = metadata_tvbuf(2, 1):bitfield(3, 5)
  local hop_len = hop_ml_words * 4
  metadata_header:add(int_hop_ml, hop_ml_words)

  metadata_header:add(int_remaining_hop_cnt, metadata_tvbuf(3, 1))

  -- Instruction bits are MSB -> LSB, matching the Python parser.
  local bit_0 = metadata_tvbuf(4, 1):bitfield(0, 1)
  local bit_1 = metadata_tvbuf(4, 1):bitfield(1, 1)
  local bit_2 = metadata_tvbuf(4, 1):bitfield(2, 1)
  local bit_3 = metadata_tvbuf(4, 1):bitfield(3, 1)
  local bit_4 = metadata_tvbuf(4, 1):bitfield(4, 1)
  local bit_5 = metadata_tvbuf(4, 1):bitfield(5, 1)
  local bit_6 = metadata_tvbuf(4, 1):bitfield(6, 1)
  local bit_7 = metadata_tvbuf(4, 1):bitfield(7, 1)

  metadata_header:add(instruction_bit_0, bit_0)
  metadata_header:add(instruction_bit_1, bit_1)
  metadata_header:add(instruction_bit_2, bit_2)
  metadata_header:add(instruction_bit_3, bit_3)
  metadata_header:add(instruction_bit_4, bit_4)
  metadata_header:add(instruction_bit_5, bit_5)
  metadata_header:add(instruction_bit_6, bit_6)
  metadata_header:add(instruction_bit_7, bit_7)
  metadata_header:add(int_rsvd_instructions, metadata_tvbuf(5, 1))
  metadata_header:add(int_rsvd_2, metadata_tvbuf(6, 2))

  if hop_len <= 0 or int_data_len <= 0 then
    return
  end

  -- Cap the declared INT stack length at the number of bytes actually captured.
  -- This mirrors stack_end_captured = min(...) in the Python parser.
  local available_stack_len = metadata_tvbuf:len() - INT_MD_LEN
  if available_stack_len <= 0 then
    return
  end

  local stack_len = math.min(int_data_len, available_stack_len)
  if stack_len < hop_len then
    return
  end

  local stack_tvbuf = metadata_tvbuf(INT_MD_LEN, stack_len):tvb()
  local full_hops = math.floor(stack_len / hop_len)

  for hop_index = 0, full_hops - 1 do
    local hop_start = hop_index * hop_len

    -- Every iteration is restricted to exactly one hop. This prevents a field
    -- from spilling into the next hop or beyond the captured stack.
    local hop_range = stack_tvbuf(hop_start, hop_len)
    local hop_tvbuf = hop_range:tvb()
    local metadata = metadata_header:add(p_intstackproto, hop_range)
    metadata:append_text(" (Hop " .. tostring(hop_index + 1) .. ")")

    local offset = 0
    local valid_hop = true
    local raw_hop_latency = nil
    local ingress_ts_value = nil
    local egress_ts_value = nil

    if bit_0 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        metadata:add(int_switch_id, hop_tvbuf(offset, 4))
        offset = offset + 4
      end
    end

    if valid_hop and bit_1 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        metadata:add(int_ingress_port, hop_tvbuf(offset, 2))
        metadata:add(int_egress_port, hop_tvbuf(offset + 2, 2))
        offset = offset + 4
      end
    end

    if valid_hop and bit_2 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        -- Keep the on-wire latency value temporarily. The Python parser
        -- overwrites this field with egress_ts - ingress_ts when both
        -- timestamps are present, so we do the same below.
        raw_hop_latency = hop_tvbuf(offset, 4):uint()
        offset = offset + 4
      end
    end

    if valid_hop and bit_3 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        metadata:add(int_queue_id, hop_tvbuf(offset, 1))
        metadata:add(int_queue_occ, hop_tvbuf(offset + 1, 3))
        offset = offset + 4
      end
    end

    if valid_hop and bit_4 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        ingress_ts_value = hop_tvbuf(offset, 4):uint()
        metadata:add(int_ingress_ts, hop_tvbuf(offset, 4))
        offset = offset + 4
      end
    end

    if valid_hop and bit_5 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        egress_ts_value = hop_tvbuf(offset, 4):uint()
        metadata:add(int_egress_ts, hop_tvbuf(offset, 4))
        offset = offset + 4
      end
    end

    -- These two fields are not decoded yet, but each occupies one 4-byte
    -- metadata word. Consume them so the logical offset matches the Python
    -- parser and the INT instruction bitmap.
    if valid_hop and bit_6 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        offset = offset + 4
      end
    end

    if valid_hop and bit_7 == 1 then
      if offset + 4 > hop_len then
        valid_hop = false
      else
        offset = offset + 4
      end
    end

    -- Match the Python parser exactly: when both timestamps are present,
    -- replace the on-wire hop-latency value with their unsigned 32-bit
    -- difference (including wraparound).
    if valid_hop then
      if ingress_ts_value ~= nil and egress_ts_value ~= nil then
        local computed_latency
        if egress_ts_value >= ingress_ts_value then
          computed_latency = egress_ts_value - ingress_ts_value
        else
          computed_latency = (0xFFFFFFFF - ingress_ts_value) + egress_ts_value + 1
        end
        local latency_item = metadata:add(int_hop_latency, computed_latency)
        if latency_item ~= nil then latency_item:set_generated() end
      elseif raw_hop_latency ~= nil then
        local latency_item = metadata:add(int_hop_latency, raw_hop_latency)
        if latency_item ~= nil then latency_item:set_generated() end
      end
    end

    -- If the instruction bitmap demands more bytes than Hop ML permits, stop
    -- decoding further hops. Most importantly, do not perform an out-of-range
    -- TvbRange access.
    if not valid_hop then
      break
    end
  end
end

-- Full-frame telemetry postdissector
--
-- IMPORTANT: packet length fields in these telemetry captures are not treated
-- as authoritative bounds.  In particular, this dissector does NOT use:
--   * outer IPv4 Total Length
--   * outer UDP Length
--   * inner IPv4 Total Length
--   * inner UDP Length
-- to decide where captured data ends.
--
-- Instead it walks protocol headers structurally from the COMPLETE captured
-- Ethernet frame and uses tvbuf:len() as the available-byte boundary.  This
-- matches the companion Python parser, which starts with RawPcapReader's full
-- captured frame and slices inner_bytes through the end of those captured
-- bytes.
--
-- The postdissector form is intentional.  A dissector registered only on
-- udp.port 5900 receives the UDP payload TVB that Wireshark has already bounded
-- according to normal IP/UDP dissection.  That can hide bytes Wireshark labels
-- as Ethernet trailer when the recorded length fields are stale.  A
-- postdissector receives the full captured frame TVB, so those captured bytes
-- remain available for INT parsing.
function p_telemetryproto.dissector(tvbuf, pktinfo, root)
  local frame_len = tvbuf:len()

  -- Outer Ethernet
  if frame_len < ETH_LEN then
    return
  end

  local outer_eth_type = tvbuf(12, 2):uint()
  local outer_offset = ETH_LEN

  -- Outer VLAN / QinQ tags.  Walk tags structurally; do not trust any length
  -- declaration to bound the frame.
  while outer_eth_type == 0x8100 or outer_eth_type == 0x88A8 or outer_eth_type == 0x9100 do
    if frame_len < outer_offset + VLAN_LEN then
      return
    end
    outer_eth_type = tvbuf(outer_offset + 2, 2):uint()
    outer_offset = outer_offset + VLAN_LEN
  end

  if outer_eth_type ~= 0x0800 then
    return
  end

  -- Outer IPv4.  We honor IHL because it is structural header information, but
  -- intentionally ignore IPv4 Total Length as a captured-byte boundary.
  if frame_len < outer_offset + IPV4_MIN_LEN then
    return
  end

  local outer_version_ihl = tvbuf(outer_offset, 1):uint()
  local outer_ip_version = math.floor(outer_version_ihl / 16)
  local outer_ip_ihl = outer_version_ihl % 16
  local outer_ip_header_len = outer_ip_ihl * 4

  if outer_ip_version ~= 4 or outer_ip_header_len < IPV4_MIN_LEN then
    return
  end

  if frame_len < outer_offset + outer_ip_header_len then
    return
  end

  local outer_ip_proto = tvbuf(outer_offset + 9, 1):uint()
  if outer_ip_proto ~= 17 then
    return
  end

  -- Outer UDP.  Check only that the fixed header is captured and that the
  -- destination port is our telemetry port.  DO NOT use the UDP Length field.
  local outer_udp_offset = outer_offset + outer_ip_header_len
  if frame_len < outer_udp_offset + UDP_LEN then
    return
  end

  local outer_dst_port = tvbuf(outer_udp_offset + 2, 2):uint()
  if outer_dst_port ~= 5900 then
    return
  end

  -- Telemetry report starts immediately after the fixed 8-byte outer UDP
  -- header, irrespective of the UDP Length field.
  local telemetry_offset = outer_udp_offset + UDP_LEN
  if frame_len < telemetry_offset + TELEMETRY_REPORT_LEN + ETH_LEN then
    return
  end

  -- Telemetry report header (16 bytes)
  local subtree = root:add(
    p_telemetryproto,
    tvbuf(telemetry_offset, TELEMETRY_REPORT_LEN)
  )
  local report_header = subtree:add(
    f_report_header,
    tvbuf(telemetry_offset, TELEMETRY_REPORT_LEN)
  )

  report_header:add(f_version, tvbuf(telemetry_offset, 1):bitfield(0, 4))
  local length = tvbuf(telemetry_offset, 1):bitfield(4, 4) * 4
  report_header:add(f_length, length)

  local next_proto = tvbuf(telemetry_offset + 1, 1):bitfield(0, 3)
  report_header:add(f_next_proto, next_proto)
  report_header:add(f_rep_m_bits, tvbuf(telemetry_offset + 1, 2):bitfield(4, 6))
  report_header:add(f_rsvd_1, tvbuf(telemetry_offset + 2, 1):bitfield(2, 6))
  report_header:add(f_drop, tvbuf(telemetry_offset + 3, 1):bitfield(0, 1))
  report_header:add(f_queue, tvbuf(telemetry_offset + 3, 1):bitfield(1, 1))
  report_header:add(f_flow, tvbuf(telemetry_offset + 3, 1):bitfield(2, 1))
  report_header:add(f_hw_id, tvbuf(telemetry_offset + 3, 1):bitfield(2, 6))
  report_header:add(f_switch_id, tvbuf(telemetry_offset + 4, 4))
  report_header:add(f_seq_num, tvbuf(telemetry_offset + 8, 4))
  report_header:add(f_ingress_ts, tvbuf(telemetry_offset + 12, 4))

  -- Inner Ethernet starts immediately after the fixed telemetry report header.
  -- Crucially, this range extends to the END OF THE CAPTURED FRAME, not to the
  -- end implied by outer IP/UDP length fields.
  local inner_start = telemetry_offset + TELEMETRY_REPORT_LEN
  local inner_len = frame_len - inner_start
  if inner_len < ETH_LEN then
    return
  end

  local inner_ethernet = tvbuf(inner_start, inner_len):tvb()

  -- Parse inner Ethernet/VLAN structure directly from the full-frame buffer so
  -- all offsets are absolute and independent of Wireshark's normal payload
  -- bounding.
  local inner_eth_type = tvbuf(inner_start + 12, 2):uint()
  local inner_offset = ETH_LEN

  while inner_eth_type == 0x8100 or inner_eth_type == 0x88A8 or inner_eth_type == 0x9100 do
    if inner_len < inner_offset + VLAN_LEN then
      return
    end
    inner_eth_type = tvbuf(inner_start + inner_offset + 2, 2):uint()
    inner_offset = inner_offset + VLAN_LEN
  end

  if inner_eth_type ~= 0x0800 then
    return
  end

  -- Inner IPv4.  Honor IHL because it locates the L4 header; ignore Total
  -- Length as an available-byte boundary.
  if inner_len < inner_offset + IPV4_MIN_LEN then
    return
  end

  local inner_ip_abs = inner_start + inner_offset
  local inner_version_ihl = tvbuf(inner_ip_abs, 1):uint()
  local inner_ip_version = math.floor(inner_version_ihl / 16)
  local inner_ip_ihl = inner_version_ihl % 16
  local inner_ip_header_len = inner_ip_ihl * 4

  if inner_ip_version ~= 4 or inner_ip_header_len < IPV4_MIN_LEN then
    return
  end

  if inner_len < inner_offset + inner_ip_header_len then
    return
  end

  local inner_ip_proto = tvbuf(inner_ip_abs + 9, 1):uint()
  local l4_rel = inner_offset + inner_ip_header_len
  local int_rel = nil

  if inner_ip_proto == 6 then
    -- Match the Python parser exactly: INT starts after the collector's fixed
    -- minimum 20-byte TCP header.  TCP data-offset is recorded metadata but is
    -- not used to locate INT in this collector layout.
    if inner_len < l4_rel + TCP_FIXED_LEN then
      return
    end
    int_rel = l4_rel + TCP_FIXED_LEN

  elseif inner_ip_proto == 17 then
    -- Match Python: INT starts after the fixed 8-byte UDP header.  Do not use
    -- the inner UDP Length field.
    if inner_len < l4_rel + UDP_LEN then
      return
    end
    int_rel = l4_rel + UDP_LEN

  else
    return
  end

  local int_abs = inner_start + int_rel

  -- Need at least shim + metadata header in CAPTURED bytes.
  if frame_len < int_abs + INT_SHIM_LEN + INT_MD_LEN then
    return
  end

  -- Validate the same shim-length byte used by Python.  Still do not use any
  -- IP/UDP packet length declaration as a bound.
  local shim_len_words = tvbuf(int_abs + 2, 1):uint()
  if shim_len_words < 3 then
    return
  end

  -- Decode the encapsulated inner Ethernet frame for display.  Wireshark may
  -- still label some final bytes as trailer according to stale inner lengths;
  -- that visual interpretation does NOT constrain the INT parser below.
  local eth_dis = Dissector.get("eth_withoutfcs")
  if eth_dis ~= nil then
    eth_dis:call(inner_ethernet, pktinfo, root)
  end

  -- INT parser gets EVERY captured byte from the computed INT offset through
  -- the end of the frame.  p_intshimproto then limits itself using INT's own
  -- shim length / Hop ML, not IP or UDP length fields.
  local all_int_len = frame_len - int_abs
  if all_int_len < INT_SHIM_LEN + INT_MD_LEN then
    return
  end

  local all_int = tvbuf(int_abs, all_int_len):tvb()
  p_intshimproto.dissector(all_int, pktinfo, root)

  pktinfo.cols.protocol:set("INT")
end

-- Initialization routine
function p_telemetryproto.init()
end

-- Register as a POSTDISSECTOR so tvbuf is the COMPLETE captured Ethernet
-- frame.  Do not also register on udp.port 5900; doing so would put us back on
-- Wireshark's length-bounded UDP payload TVB and could decode the packet twice.
register_postdissector(p_telemetryproto)
