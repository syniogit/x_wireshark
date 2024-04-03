-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2024. L. Van Deuren <luc.van.deuren@gmail.com>
-- 
-- description:
-- protocol decoding for DoIP
-- ISO 13400-2:2012, DOIP version 2

local SIGp = "x-"
local SIGB = "X-"

local my_info = {
     version = "2024-04-03",
     author = "L. Van Deuren<luc.van.deuren@gmaiL.com>",
     repository = "https://github.com/syniogit/x_wireshark",
     spdx_id = "GPL-2.0-or-later",
     description = "DoIP lua dissector for wireshark"
}

set_plugin_info(my_info)

p_doip_udp = Proto(SIGp .. "doip_udp", SIGB .. "DOIP_udp")
p_doip_tcp = Proto(SIGp .. "doip_tcp", SIGB .. "DOIP_tcp")
p_doip = Proto(SIGp .. "doip", SIGB .. "DOIP")

p_doip_udp.prefs["udp_port"] = Pref.uint("UDP Port",13400,"UDP Port for DOIP")
local f_udp_version = ProtoField.uint8(SIGp .. "doip.udp_version", "version", base.HEX)
local f_udp_iversion = ProtoField.uint8(SIGp .. "doip.udp_iversion", "iversion", base.HEX)
local f_udp_type = ProtoField.uint16(SIGp .. "doip.udp_type", "type", base.HEX)
local f_udp_length = ProtoField.uint32(SIGp .. "doip.udp_length", "length", base.DEC)

local f_tcp_version = ProtoField.uint8(SIGp .. "doip.tcp_version", "version", base.HEX)
local f_tcp_iversion = ProtoField.uint8(SIGp .. "doip.tcp_iversion", "iversion", base.HEX)
local f_tcp_type = ProtoField.uint16(SIGp .. "doip.tcp_type", "type", base.HEX)
local f_tcp_length = ProtoField.uint32(SIGp .. "doip.tcp_length", "length", base.DEC)

local f_version = ProtoField.uint8(SIGp .. "doip.version", "version", base.HEX)
local f_iversion = ProtoField.uint8(SIGp .. "doip.iversion", "iversion", base.HEX)
local f_type = ProtoField.uint16(SIGp .. "doip.type", "type", base.HEX)
local f_length = ProtoField.uint32(SIGp .. "doip.length", "length", base.DEC)
local f_sa = ProtoField.uint16(SIGp .. "doip.sa", "sa", base.HEX)
local f_ta = ProtoField.uint16(SIGp .. "doip.ta", "ta", base.HEX)
local f_nack = ProtoField.uint8(SIGp .. "doip.nack", "nack", base.HEX)
local f_eid = ProtoField.bytes(SIGp .. "doip.eid", "eid")
local f_gid = ProtoField.bytes(SIGp .. "doip.gid", "gid")
local f_vin = ProtoField.string(SIGp .. "doip.vin", "vin")
local f_action_code = ProtoField.uint8(SIGp .. "doip.action_code", "action_code", base.HEX)
local f_sync_status = ProtoField.uint8(SIGp .. "doip.sync_status", "sync_status", base.HEX)
local f_activation_type = ProtoField.uint8(SIGp .. "doip.activation_type", "activation_type", base.HEX)
local f_activation_reserved = ProtoField.bytes(SIGp .. "doip.activation_reserved", "activation_reserved")
local f_activation_manufacturer = ProtoField.bytes(SIGp .. "doip.activation_manufacturer", "manufacturer")
local f_activation_response_code = ProtoField.uint8(SIGp .. "doip.activation_response_code", "activation_response_code", base.HEX)
local f_status_node_type = ProtoField.uint8(SIGp .. "doip.status_node_type", "node_type", base.HEX)
local f_status_max_sockets = ProtoField.uint8(SIGp .. "doip.status_max_sockets", "max_sockets", base.DEC)
local f_status_open_sockets = ProtoField.uint8(SIGp .. "doip.status_open_sockets", "open_sockets", base.DEC)
local f_status_max_data_size = ProtoField.uint32(SIGp .. "doip.status_max_data_size", "max_data_size", base.DEC)
local f_diag_ack = ProtoField.uint8(SIGp .. "doip.diag_ack", "ack", base.HEX)
local f_diag_nack = ProtoField.uint8(SIGp .. "doip.diag_nack", "nack", base.HEX)
local f_diag_data = ProtoField.bytes(SIGp .. "doip.diag_data", "data")

p_doip_udp.fields = {
	f_udp_version,
	f_udp_iversion,
	f_udp_type,
	f_udp_length
}
p_doip_tcp.fields = {
	f_tcp_version,
	f_tcp_iversion,
	f_tcp_type,
	f_tcp_length
}

p_doip.fields = {
	f_version,
	f_iversion,
	f_type,
	f_length,
	f_sa,
	f_ta,
	f_nack,
	f_eid,
	f_gid,
	f_vin,
	f_action_code,
	f_sync_status,
	f_activation_type,
	f_activation_reserved,
	f_activation_manufacturer,
	f_activation_response_code,
	f_status_node_type,
	f_status_max_sockets,
	f_status_open_sockets,
	f_status_max_data_size,
	f_diag_ack,
	f_diag_nack,
	f_diag_data
}

local f_type_strings = {
	[0x0000] = "GenericNack",
	[0x0001] = "VehicleIdentifcation",
	[0x0002] = "VehicleIdentification_with_EID",
	[0x0003] = "VehicleIdentification_with_VIN",
	[0x0004] = "VehicleAnnouncement",
	[0x0005] = "RoutingActivationRequest",
	[0x0006] = "RoutingActivationResponse",
	[0x0007] = "AliveCheckRequest",
	[0x0008] = "AliveCheckResponse",
	[0x4001] = "StatusRequest",
	[0x4002] = "StatusResponse",
	[0x4003] = "PowerModeInformationRequest",
	[0x4004] = "PowerModeInformationResponse",
	[0x8001] = "DiagnosticRequest",
	[0x8002] = "DiagnosticAck",
	[0x8003] = "DiagnosticNack"
}

local f_nack_code_strings = {
	[0x00] = "Incorrect pattern format",
	[0x01] = "Unknown payload type",
	[0x02] = "Message too large",
	[0x03] = "Out of memory",
	[0x04] = "Invalid payload length"
}

local f_action_code_strings = {
	[0x00] = "No further action required",
	[0x10] = "Routing activation required"
}

local f_activation_type_strings = {
	[0x00] = "Default",
	[0x01] = "WWH-OBD",
	[0xE0] = "Central Security"
}

local f_activation_response_code_strings = {
	[0x00] = "Denied due to unknown source address",
	[0x01] = "Denied because all concurrently supported TCP_DATA sockets are registered and active",
	[0x02] = "Denied because an SA different from the table connection entry was received on the already activated TCP_DATA socket",
	[0x03] = "Denied because the SA is already registered and active on a different TCP_DATA socket",
	[0x04] = "Denied due to missing authentication",
	[0x05] = "Denied due to rejected confirmation",
	[0x06] = "Denied due to unsupported activation type",
	[0x10] = "Success",
	[0x11] = "Routing will be activated; confirmation required"
}

local f_power_mode_strings = {
	[0x00] = "Not ready",
	[0x01] = "Ready",
	[0xE0] = "Not supported"
}

local f_diag_ack_strings = {
	[0x00] = "Routing confirmation acknowledged"
}

local f_diag_nack_strings = {
	[0x02] = "Invalid source address",
	[0x03] = "Unknown target address",
	[0x04] = "Diagnostic message too large",
	[0x05] = "Out of memory",
	[0x06] = "Target unreachable",
	[0x07] = "Unknown network",
	[0x08] = "Transport protocol error"
}

local uds_dissector = nil;
local data_dissector = nil;

function p_doip_udp.init()
	--print("INIT UDP")
end

function p_doip_tcp.init()
	--print("INIT TCP")
end

function p_doip.init()
	--print("INIT")

	local udp_dissector_table = DissectorTable.get("udp.port")
	local tcp_dissector_table = DissectorTable.get("tcp.port")

	for i,port in ipairs{13400} do
		udp_dissector_table:add(port, p_doip_udp)
		tcp_dissector_table:add(port, p_doip_tcp)
	end
	
	-- lookup UDS
	result, uds_dissector = pcall(Dissector.get, SIGp .. "uds") 
	if result == false then
		print("Could not find \"uds_" .. SIGp .. "\" dissector!")
		uds_dissector = nil
	end
	result, data_dissector = pcall(Dissector.get, "data")
	if result == false then
		print("Could not find \"data\" dissector")
		data_dissector = nil
	end
end

function p_doip_udp.dissector(buf,info,tree)

	info.cols.protocol = SIGB .. "DOIP_udp"
	
	return p_doip.dissector:call(buf,info,tree)
	
end

function p_doip_tcp.dissector(buf,info,tree)

	info.cols.protocol = SIGB .. "DOIP_tcp"	
	
	local offset = 0
	-- subtree 8 bytes
--	local subtree = tree:add(p_doip,buf(offset,8))

	-- version
	local version = buf(offset, 1):uint()
--	local f_version_subtree = subtree:add(f_version, buf(offset,1))
	offset = offset + 1
	-- iversion	
	local iversion = buf(offset, 1):uint()
--	local f_iversion_subtree = subtree:add(f_iversion, buf(offset,1))
	offset = offset + 1

	--  f_type	
--	local f_type_subtree = subtree:add(f_type, buf(offset,2))
	local v_type = buf(offset,2):uint()
	if f_type_strings[buf(offset,2):uint()] ~= nil then
		info.cols.protocol:append(" " .. f_type_strings[buf(offset, 2):uint()])
--		subtree:append_text(" "..f_type_strings[buf(offset,2):uint()])
--		f_type_subtree:append_text(" " .. f_type_strings[buf(offset,2):uint()])
	else
		info.cols.protocol:append(" Type: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
--		subtree:append_text(" 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	end
	offset = offset + 2 
	
	-- f_length
	local length = buf(offset,4):uint()
--	subtree:add(f_length, buf(offset,4))
	offset = offset + 4 

--	subtree:set_len(8+length)

	local expected = offset+length	
	if expected > buf():len() then
		print("need more: expected=".. expected .. " buf=".. buf:len())
		info.cols.protocol:append(" need more: expected=".. expected .. " buf=".. buf:len())
		info.desegment_len = expected - buf():len()
		info.desegment_offset = 0 
		return 
	end

	if buf():len() > expected then
		print("too much")
		info.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		info.desegment_offset = expected 
		info.cols.protocol:append(" too much expected=" .. expected .. " buf=" .. buf():len())
	end

	
	buffer = buf:range(0, expected)
	print("VER=".. string.format("%02x", version) .. " IVER=" .. string.format("%02x", iversion) .. " v_type=" .. string.format("%04x", v_type) .. " len=".. length)	
	print("OK : TOTAL expected=".. expected .. " buffer=" .. buffer():len() .. " buf=".. buf:len())
	info.cols.protocol:append(" OK : TOTAL expected=".. expected .. " buffer=" .. buffer():len().. " buf=".. buf:len())
	
	return p_doip.dissector:call(buffer():tvb(),info,tree)
end

function p_doip.dissector(buf,info,tree)

	info.cols.protocol = SIGB .. "DOIP"	
	
	local offset = 0
	-- subtree 8 bytes
	local subtree = tree:add(p_doip,buf(offset,8))

	-- version	
	local f_version_subtree = subtree:add(f_version, buf(offset,1))
	offset = offset + 1
	-- iversion	
	local f_iversion_subtree = subtree:add(f_iversion, buf(offset,1))
	offset = offset + 1

	--  f_type	
	local f_type_subtree = subtree:add(f_type, buf(offset,2))
	local v_type = buf(offset,2):uint()
	if f_type_strings[buf(offset,2):uint()] ~= nil then
		info.cols.protocol:append(" " .. f_type_strings[buf(offset, 2):uint()])
		subtree:append_text(" "..f_type_strings[buf(offset,2):uint()])
		f_type_subtree:append_text(" " .. f_type_strings[buf(offset,2):uint()])
	else
		info.cols.protocol:append(" Type: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
		subtree:append_text(" 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	end
	offset = offset + 2 
	
	-- f_length
	local length = buf(offset,4):uint()
	subtree:add(f_length, buf(offset,4))
	offset = offset + 4 

	subtree:set_len(8+length)
	
	if v_type == 0x0000 then
		generic_nack(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0001 then
		vehicle_identification(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0002 then
		vehicle_identification_with_eid(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0003 then
		vehicle_identification_with_vin(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0004 then
		vehicle_announcement(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0005 then
		routing_activation_request(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0006 then
		routing_activation_response(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0007 then
		alive_check_request(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x0008 then
		alive_check_response(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x4001 then
		status_request(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x4002 then
		status_check_response(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x4003 then
		power_mode_information_request(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x4004 then
		power_mode_information_response(buf(offset):tvb(),info,subtree)
	elseif v_type == 0x8001 then
		diagnostic_request(buf(offset):tvb(),info,subtree,tree,length)
	elseif v_type == 0x8002 then
		diagnostic_ack(buf(offset):tvb(),info,subtree,tree,length)
	elseif v_type == 0x8003 then
		diagnostic_nack(buf(offset):tvb(),info,subtree,tree,length)
	end
	
	return offset 
end



local function handle_uds(prefix,buf,info,tree)
	local offset = 0
	if (buf:len() == 0) then
		return 0
	end
	if (uds_dissector ~= nil) then
		local len = uds_dissector:call(buf(offset):tvb(),info,tree)
		offset = offset + len
	else
--		if (data_dissector ~= nil) then
--			local len = data_dissector:call(buf(offset):tvb(),info,tree)
--			offset = offset + len
--		else
			subtree = tree:add(f_diag_data,buf(offset))
			tree:append_text(", Uds: " .. buf(offset))
			offset = offset + buf(offset):len()
--		end
	end
	return offset
end

function generic_nack(buf,info,tree)
	local offset = 0
	
	local subtree = tree:add(f_nack,buf(offset,1))
	if f_nack_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_nack_code_strings[buf(offset,1):uint()])
		tree:append_text(", Code: " .. f_nack_code_strings[buf(offset,1):uint()])
	else
		subtree:append_text(" Reserved")
		tree:append_text(", Code: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1

	return offset 
end

function vehicle_identification(buf,info,tree)
	return 0
end

function vehicle_identification_with_eid(buf,info,tree)
	local offset = 0

	tree:add(f_eid,buf(offset,6))
	tree:append_text(", EID: 0x" .. bit.tohex(buf(offset,6):uint(),12))
	offset = offset + 6

	return offset 
end

function vehicle_identification_with_vin(buf,info,tree)
	local offset = 0
	
	tree:add(f_vin,buf(offset,17))
	tree:append_text(", Vin: '" .. buf(offset,17) .. "'")
	offset = offset + 17

	return offset 
end

function vehicle_announcement(buf,info,tree)
	local offset = 0

	tree:add(f_vin,buf(offset,17))
	tree:append_text(", VIN: " .. string.format("\"%s\"",  buf(offset,17):string()))
	offset = offset + 17

	tree:add(f_ta,buf(offset,2))
	tree:append_text(", TA: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	offset = offset + 2 

	tree:add(f_eid,buf(offset,6))
	tree:append_text(", EID: 0x" .. buf(offset,6))
	offset = offset + 6

	subtree = tree:add(f_gid,buf(offset,6))
	tree:append_text(", GID: 0x" .. buf(offset,6))
	offset = offset + 6

	local f_action_code_subtree = tree:add(f_action_code,buf(offset,1))
	if f_action_code_strings[buf(offset,1):uint()] ~= nil then
		f_action_code_subtree:append_text(" " .. f_action_code_strings[buf(offset,1):uint()])
		tree:append_text(", ActionCode: " .. f_action_code_strings[buf(offset,1):uint()])
	else
		f_action_code_subtree:append_text(" 0x" .. bit.tohex(buf(offset,1):uint(),2))
		tree:append_text(", ActionCode: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	-- optional sync status
	if (buf(offset):len() > 0) then
		local subtree = tree:add(f_sync_status,buf(offset,1))
		tree:append_text(", SyncStatus: 0x" .. bit.tohex(buf(offset,1):uint(),2))
		if f_nack_strings[buf(offset,1):uint()] ~= nil then
			subtree:append_text(", SyncStatus: " .. f_sync_status_code_strings[buf(offset,1):uint()])
			tree:append_text(", SyncStatus: " .. f_sync_status_code_strings[buf(offset,1):uint()])
		else
			tree:append_text(", SyncStatus: 0x" .. bit.tohex(buf(offset,1):uint(),2))
		end
		offset = offset + 1 
	end

	return offset 
end

function routing_activation_request(buf,info,tree)
	local offset = 0

	tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	offset = offset + 2 
	
	local subtree = tree:add(f_activation_type,buf(offset,1))
	if f_activation_type_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_activation_type_strings[buf(offset,1):uint()])
		tree:append_text(", ActivationType: " .. f_activation_type_strings[buf(offset,1):uint()])
	else
		subtree:append_text(" Reserved")
		tree:append_text(", ActivationType: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	--- 0x00000000 reserved mandatory
	tree:add(f_activation_reserved,buf(offset,4))
	offset = offset + 4

	-- 0x........ manufaturer optional
	if (buf(offset):len() > 3) then
		tree:add(f_activation_manufacturer,buf(offset,4))
		offset = offset + 4
	end

	return offset 
end

function routing_activation_response(buf,info,tree)
	local offset = 0

	tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	offset = offset + 2 
	
	tree:add(f_ta,buf(offset,2))
	tree:append_text(", TA: 0x" .. bit.tohex(buf(offset,2):uint(), 4))
	offset = offset + 2 
	
	local v_response_code = buf(offset,1):uint()
	local subtree = tree:add(f_activation_response_code,buf(offset,1))
	if f_activation_response_code_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_activation_response_code_strings[buf(offset,1):uint()])
		tree:append_text(", ActivationResponseCode: " .. f_activation_response_code_strings[buf(offset,1):uint()])
	else
		if ((v_response_code >= 0x7) and (v_response_code <= 0x0f)) then
			subtree:append_text(" Reserved")
		end
		if ((v_response_code >= 0x12) and (v_response_code <= 0xDF)) then
			subtree:append_text(" Reserved")
		end
		if ((v_response_code >= 0xE0) and (v_response_code <= 0xFE)) then
			subtree:append_text(" Manufacturer")
		end
		if (v_response_code == 0xff) then
			subtree:append_text(" Reserved")
		end
		tree:append_text(", ActivationResponse: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	--- 0x00000000 reserved mandatory
	tree:add(f_activation_reserved,buf(offset,4))
	offset = offset + 4

	-- 0x........ manufaturer optional
	if (buf(offset):len() > 3) then
		tree:add(f_activation_manufacturer,buf(offset,4))
		offset = offset + 4
	end

	return offset 
end

function alive_check_request(buf,info,tree)
	return 0
end

function alive_check_response(buf,info,tree)
	local offset = 0
	
	local subtree = tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 

	return offset 
end

function status_request(buf,info,tree)
	return 0
end

function status_response(buf,info,tree)
	local offset = 0
	
	tree:add(f_node_type,buf(offset,1))
	tree:append_text(", NodeType: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	offset = offset + 1 
	
	tree:add(f_max_sockets,buf(offset,1))
	tree:append_text(", MaxSockets: " .. buf(offset,1):uint())
	offset = offset + 1 
	
	tree:add(f_open_sockets,buf(offset,1))
	tree:append_text(", OpenSockets: " .. buf(offset,1):uint())
	offset = offset + 1 
	
	tree:add(f_max_data_size,buf(offset,4))
	tree:append_text(", MaxDataSize: " .. buf(offset,4):uint())
	offset = offset + 4 

	return offset 
end

function power_mode_information_request(buf,info,tree)
	return 0
end

function power_mode_information_response(buf,info,tree)
	local offset = 0
	
	local subtree = tree:add(f_power_mode,buf(offset,1))
	if f_power_mode_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_power_mode_strings[buf(offset,1):uint()])
		tree:append_text(", PowerMode: " .. f_power_mode_strings[buf(offset,1):uint()])
	else
		subtree:append_text(" Reserved")
		tree:append_text(", PowerMode: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	return offset 
end

function diagnostic_request(buf,info,tree,parent,length)
	local offset = 0

	subtree = tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 
	
	subtree = tree:add(f_ta,buf(offset,2))
	tree:append_text(", TA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 

	local len = handle_uds("Data", buf(offset),info,parent)
	offset = offset + len
	
	return offset
end

function diagnostic_ack(buf,info,tree,parent)
	local offset = 0

	subtree = tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 
	
	subtree = tree:add(f_ta,buf(offset,2))
	tree:append_text(", TA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 

	local subtree = tree:add(f_diag_ack,buf(offset,1))
	if f_diag_ack_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_diag_ack_strings[buf(offset,1):uint()])
		tree:append_text(", DiagAck: " .. f_diag_ack_strings[buf(offset,1):uint()])
	else
		subtree:append_text(" Reserved")
		tree:append_text(", DiagAck: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	return offset 
end

function diagnostic_nack(buf,info,tree,parent)
	local offset = 0

	subtree = tree:add(f_sa,buf(offset,2))
	tree:append_text(", SA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 
	
	local subtree = tree:add(f_ta,buf(offset,2))
	tree:append_text(", TA: 0x" .. bit.tohex(buf(offset,2):uint(),4))
	offset = offset + 2 

	local subtree = tree:add(f_diag_nack,buf(offset,1))
	if f_diag_nack_strings[buf(offset,1):uint()] ~= nil then
		subtree:append_text(" " .. f_diag_nack_strings[buf(offset,1):uint()])
		tree:append_text(", DiagNack: " .. f_diag_nack_strings[buf(offset,1):uint()])
	else
		subtree:append_text(" Reserved")
		tree:append_text(", DiagNack: 0x" .. bit.tohex(buf(offset,1):uint(),2))
	end
	offset = offset + 1 

	return offset 
end

