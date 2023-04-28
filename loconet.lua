--[[

LocoNet protocol dissector for WireShark

Copyright (C) 2023 Reinder Feenstra

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

]]

--[[

Based on LocoNet Personal Use Edition 1.0 SPECIFICATION by Digitrax Inc.

]]

local loconet = Proto("loconet", "LocoNet")

-- 2 byte message opcodes:
local OPC_BUSY = 0x81
local OPC_GPOFF = 0x82
local OPC_GPON = 0x83
local OPC_IDLE = 0x85

-- 4 byte message opcodes:
local OPC_LOCO_SPD = 0xA0
local OPC_LOCO_DIRF = 0xA1
local OPC_LOCO_SND = 0xA2
local OPC_SW_REQ = 0xB0
local OPC_SW_REP = 0xB1
local OPC_INPUT_REP = 0xB2
local OPC_LONG_ACK = 0xB4
local OPC_SLOT_STAT1 = 0xB5
local OPC_CONSIST_FUNC = 0xB6
local OPC_UNLINK_SLOTS = 0xB8
local OPC_LINK_SLOTS = 0xB9
local OPC_MOVE_SLOTS = 0xBA
local OPC_RQ_SL_DATA = 0xBB
local OPC_SW_STATE = 0xBC
local OPC_SW_ACK = 0xBD
local OPC_LOCO_ADR = 0xBF

-- 6 byte message opcodes:

-- variable byte message opcodes:
local OPC_PEER_XFER = 0xE5
local OPC_SL_RD_DATA = 0xE7
local OPC_IMM_PACKET = 0xED
local OPC_WR_SL_DATA = 0xEF

local opcodes = {
  [OPC_BUSY] = "OPC_BUSY",
  [OPC_GPOFF] = "OPC_GPOFF",
  [OPC_GPON] = "OPC_GPON",
  [OPC_IDLE] = "OPC_IDLE",
  [OPC_LOCO_SPD] = "OPC_LOCO_SPD",
  [OPC_LOCO_DIRF] = "OPC_LOCO_DIRF",
  [OPC_LOCO_SND] = "OPC_LOCO_SND",
  [OPC_SW_REQ] = "OPC_SW_REQ",
  [OPC_SW_REP] = "OPC_SW_REP",
  [OPC_INPUT_REP] = "OPC_INPUT_REP",
  [OPC_LONG_ACK] = "OPC_LONG_ACK",
  [OPC_SLOT_STAT1] = "OPC_SLOT_STAT1",
  [OPC_CONSIST_FUNC] = "OPC_CONSIST_FUNC",
  [OPC_UNLINK_SLOTS] = "OPC_UNLINK_SLOTS",
  [OPC_LINK_SLOTS] = "OPC_LINK_SLOTS",
  [OPC_MOVE_SLOTS] = "OPC_MOVE_SLOTS",
  [OPC_RQ_SL_DATA] = "OPC_RQ_SL_DATA",
  [OPC_SW_STATE] = "OPC_SW_STATE",
  [OPC_SW_ACK] = "OPC_SW_ACK",
  [OPC_LOCO_ADR] = "OPC_LOCO_ADR",
  [OPC_PEER_XFER] = "OPC_PEER_XFER",
  [OPC_SL_RD_DATA] = "OPC_SL_RD_DATA",
  [OPC_IMM_PACKET] = "OPC_IMM_PACKET",
  [OPC_WR_SL_DATA] = "OPC_WR_SL_DATA",
}
local function_on_off = {[0] = "Off", [1] = "On"}

local pf_opcode = ProtoField.uint8("loconet.opcode", "OpCode", base.HEX, opcodes)
local pf_length = ProtoField.uint8("loconet.length", "Length", base.DEC)
local pf_slot = ProtoField.uint8("loconet.slot", "Slot", base.DEC)
local pf_speed = ProtoField.uint8("loconet.speed", "Speed", base.DEC)
local pf_dirf = ProtoField.none("loconet.dirf", "DirF")
local pf_dirf_dir = ProtoField.uint8("loconet.dirf.dir", "Direction", base.DEC, {[0] = "Reverse", [1] = "Forward"}, 0x20)
local pf_dirf_f0 = ProtoField.uint8("loconet.dirf.f0", "F0", base.DEC, function_on_off, 0x10)
local pf_dirf_f1 = ProtoField.uint8("loconet.dirf.f1", "F1", base.DEC, function_on_off, 0x01)
local pf_dirf_f2 = ProtoField.uint8("loconet.dirf.f2", "F2", base.DEC, function_on_off, 0x02)
local pf_dirf_f3 = ProtoField.uint8("loconet.dirf.f3", "F3", base.DEC, function_on_off, 0x04)
local pf_dirf_f4 = ProtoField.uint8("loconet.dirf.f4", "F4", base.DEC, function_on_off, 0x08)
local pf_snd = ProtoField.none("loconet.snd", "Snd")
local pf_snd_f5 = ProtoField.uint8("loconet.snd.f5", "F5", base.DEC, function_on_off, 0x01)
local pf_snd_f6 = ProtoField.uint8("loconet.snd.f6", "F6", base.DEC, function_on_off, 0x02)
local pf_snd_f7 = ProtoField.uint8("loconet.snd.f7", "F7", base.DEC, function_on_off, 0x04)
local pf_snd_f8 = ProtoField.uint8("loconet.snd.f8", "F8", base.DEC, function_on_off, 0x08)
local pf_checksum = ProtoField.uint8("loconet.checksum", "Checksum", base.HEX)

loconet.fields = {
  pf_opcode,
  pf_length,
  pf_slot,
  pf_speed,
  pf_dirf,
  pf_dirf_dir,
  pf_dirf_f0,
  pf_dirf_f1,
  pf_dirf_f2,
  pf_dirf_f3,
  pf_dirf_f4,
  pf_snd,
  pf_snd_f5,
  pf_snd_f6,
  pf_snd_f7,
  pf_snd_f8,
  pf_checksum,
}

function add_dirf(tree, dirf)
  local subtree = tree:add(pf_dirf, dirf)
  subtree:add(pf_dirf_dir, dirf)
  subtree:add(pf_dirf_f0, dirf)
  subtree:add(pf_dirf_f1, dirf)
  subtree:add(pf_dirf_f2, dirf)
  subtree:add(pf_dirf_f3, dirf)
  subtree:add(pf_dirf_f4, dirf)
end

function add_snd(tree, snd)
  local subtree = tree:add(pf_snd, snd)
  subtree:add(pf_snd_f5, snd)
  subtree:add(pf_snd_f6, snd)
  subtree:add(pf_snd_f7, snd)
  subtree:add(pf_snd_f8, snd)
end

function opc_busy(tree, tvbuf)
  return "Busy"
end

function opc_gpoff(tree, tvbuf)
  return "Global power: Off"
end

function opc_gpon(tree, tvbuf)
  return "Global power: On"
end

function opc_idle(tree, tvbuf)
  return "Idle"
end

function opc_loco_spd(tree, tvbuf)
  local slot = tvbuf:range(1, 1)
  local speed = tvbuf:range(2, 1)
  tree:add(pf_slot, slot)
  tree:add(pf_speed, speed)
  return "Loco speed: slot=" .. tostring(slot:uint()) .. " speed=" .. tostring(speed:uint())
end

function opc_loco_dirf(tree, tvbuf)
  tree:add(pf_slot, tvbuf:range(1, 1))
  add_dirf(tree, tvbuf:range(2, 1))
  return "Loco dirf"
end

function opc_loco_snd(tree, tvbuf)
  tree:add(pf_slot, tvbuf:range(1, 1))
  add_snd(tree, tvbuf:range(2, 1))
  return "Loco snd"
end

function opc_sw_req(tree, tvbuf)
  return "Switch request"
end

function opc_sw_rep(tree, tvbuf)
  return "Switch reply"
end

function opc_input_rep(tree, tvbuf)
  return "Input reply"
end

function opc_long_ack(tree, tvbuf)
  return "Long ack"
end

function opc_slot_stat1(tree, tvbuf)
  return "Slot stat"
end

function opc_consist_func(tree, tvbuf)
  return "Consist func"
end

function opc_unlink_slots(tree, tvbuf)
  return "Unlink slots"
end

function opc_link_slots(tree, tvbuf)
  return "Link slots"
end

function opc_move_slots(tree, tvbuf)
  return "Move slots"
end

function opc_rq_sl_data(tree, tvbuf)
  return "Request slot data"
end

function opc_sw_state(tree, tvbuf)
  return "Switch state"
end

function opc_sw_ack(tree, tvbuf)
  return "Switch ack"
end

function opc_loco_adr(tree, tvbuf)
  return "Loco adr"
end

function opc_peer_xfer(tree, tvbuf)
  return "Peer xfer"
end

function opc_rq_sl_data(tree, tvbuf)
  local slot = tvbuf:range(1, 1)
  tree:add(pf_slot, slot)
  return "Request slot " .. tostring(slot:uint()) .. " data"
end

function opc_sl_rd_data(tree, tvbuf)
  local slot = tvbuf:range(2, 1):uint()
  tree:add(pf_slot, tvbuf:range(2, 1))

  if slot >= 1 and slot <= 119 then -- Locomotive
    add_dirf(tree, tvbuf:range(6, 1))
    add_snd(tree, tvbuf:range(9, 1))
  elseif slot == 123 then -- Fast clock

  elseif slot == 124 then -- Programming

  end

  return "Slot " .. tostring(slot) .. " data"
end

function opc_imm_packet(tree, tvbuf)
  return "IMM packet"
end

function opc_wr_sl_data(tree, tvbuf)
  local slot = tvbuf:range(2, 1)
  return "Write slot " .. tostring(slot:uint()) .. " data"
end

local handlers = {
  [OPC_BUSY] = opc_busy,
  [OPC_GPOFF] = opc_gpoff,
  [OPC_GPON] = opc_gpon,
  [OPC_IDLE] = opc_idle,
  [OPC_LOCO_SPD] = opc_loco_spd,
  [OPC_LOCO_DIRF] = opc_loco_dirf,
  [OPC_LOCO_SND] = opc_loco_snd,
  [OPC_SW_REQ] = opc_sw_req,
  [OPC_SW_REP] = opc_sw_rep,
  [OPC_INPUT_REP] = opc_input_rep,
  [OPC_LONG_ACK] = opc_long_ack,
  [OPC_SLOT_STAT1] = opc_slot_stat1,
  [OPC_CONSIST_FUNC] = opc_consist_func,
  [OPC_UNLINK_SLOTS] = opc_unlink_slots,
  [OPC_LINK_SLOTS] = opc_link_slots,
  [OPC_MOVE_SLOTS] = opc_move_slots,
  [OPC_RQ_SL_DATA] = opc_rq_sl_data,
  [OPC_SW_STATE] = opc_sw_state,
  [OPC_SW_ACK] = opc_sw_ack,
  [OPC_LOCO_ADR] = opc_loco_adr,
  [OPC_PEER_XFER] = opc_peer_xfer,
  [OPC_SL_RD_DATA] = opc_sl_rd_data,
  [OPC_IMM_PACKET] = opc_imm_packet,
  [OPC_WR_SL_DATA] = opc_wr_sl_data,
}

function loconet.dissector(tvbuf, pktinfo, root)
  pktinfo.cols.protocol:set("LocoNet")

  local tree = root:add(loconet, tvbuf)
  local opcode = tvbuf:range(0, 1):le_uint()
  tree:add(pf_opcode, tvbuf:range(0, 1))
  if bit.band(opcode, 0xE0) == 0xE0 then
    tree:add(pf_length, tvbuf:range(1, 1))
  end
  if handlers[opcode] ~= nil then
    pktinfo.cols.info:append(handlers[opcode](tree, tvbuf))
  end
  tree:add(pf_checksum, tvbuf:range(tvbuf:len() - 1, 1))
end
