-- SPDX-License-Identifier: GPL-2.0
-- Copyright (c) 2024. L. Van Deuren <luc.van.deuren@gmail.com>
-- 
-- description:
-- protocol decoding for UDS 
-- ISO 14229 protocol

local SIGp = "x-"
local SIGB = "X-"

local my_info = {
     version = "2024-04-03",
     author = "L. Van Deuren<luc.van.deuren@gmaiL.com>",
     repository = "https://github.com/syniogit/x_wireshark",
     spdx_id = "GPL-2.0-or-later",
     description = "UDS lua dissector for wireshark"
}


local SIGp = "x-"
local SIGB = "X-"

local my_info = {
     version = "1.0.0",
     author = "L. Van Deuren",
     repository = "https://github.com/syniogit/x-uds",
     spdx_id = "GPL-2.0-or-later",
     description = "UDS lua dissector for wireshark"
}

p_uds = Proto(SIGp .. "uds", SIGB .. "UDS")
uds_stats = {};

local f_sid = ProtoField.uint8(SIGp .. "uds.sid", "sid", base.HEX)
local f_nr_sid = ProtoField.uint8(SIGp .. "uds.nr_sid", "nr_sid", base.HEX)
local f_nrc = ProtoField.uint8(SIGp .. "uds.nrc", "nrc", base.HEX)
local f_session_type = ProtoField.uint8(SIGp .. "uds.session_type", "session_type", base.HEX)
local f_p2_server_max = ProtoField.uint16(SIGp .. "uds.p2_server_max", "p2_server_max", base.DEC)
local f_p2_server_max_enh = ProtoField.uint16(SIGp .. "uds.p2_server_max_enh", "p2_server_max", base.DEC)
local f_id = ProtoField.uint16(SIGp .. "uds.id", "id", base.HEX)
local f_subf = ProtoField.uint8(SIGp .. "uds.subf", "subf", base.HEX)
local f_data = ProtoField.bytes(SIGp .. "uds.data", "data", base.BYTES)
local f_dfi = ProtoField.uint8(SIGp .. "uds.dfi", "dfi", base.HEX)
local f_alfid = ProtoField.uint8(SIGp .. "uds.alfid", "alfid", base.HEX)
local f_lfid = ProtoField.uint8(SIGp .. "uds.lfid", "lfid", base.HEX)
local f_addr = ProtoField.uint64(SIGp .. "uds.addr", "addr", base.HEX)
local f_length = ProtoField.uint64(SIGp .. "uds.length", "length", base.DEC)
local f_max_block_length = ProtoField.uint64(SIGp .. "uds.max_block_length", "max_block_length", base.DEC)
local f_bsc = ProtoField.uint8(SIGp .. "uds.bsc", "bsc", base.DEC)
local f_link_control_mode_identifier = ProtoField.uint8(SIGp .. "uds.link_control_mode_identifier", "link_control_mode_identifier", base.HEX)
local f_link_record = ProtoField.uint8(SIGp .. "uds.link_record", "link_record", base.HEX)

local f_stat_reqs = ProtoField.uint32(SIGp .. "uds.stat_reqs", "stat_reqs", base.DEC)
local f_stat_bytes = ProtoField.uint32(SIGp .. "uds.stat_bytes", "stat_bytes", base.DEC)

p_uds.fields = {
	f_sid,
	f_nr_sid,
	f_nrc,
	f_session_type,
	f_p2_server_max,
	f_p2_server_max_enh,
	f_id,
	f_subf,
	f_data,
	f_dfi,
	f_alfid,
	f_lfid,
	f_addr,
	f_length,
	f_max_block_length,
	f_bsc,
	f_link_control_mode_identifier,
	f_link_record,
	f_stat_reqs,
	f_stat_bytes
}

local f_sid_strings = {
	[0x10] = "DiagnosticSessionControl",
	[0x11] = "ECUReset",
	[0x14] = "ClearDiagnosticInformation",
	[0x19] = "ReadDTCInformation",
	[0x22] = "ReadByDataIdentifier",
	[0x23] = "ReadMemoryByAddress",
	[0x24] = "ReadScalingDataByIdentifier",
	[0x27] = "SecurityAccess",
	[0x28] = "CommuncationControl",
	[0x29] = "Authentication",
	[0x2A] = "ReadDataByPeriodicIdentifier",
	[0x2C] = "DynamicallyDefineDataIdentifier",
	[0x2E] = "WriteDataByIdentifier",
	[0x2F] = "InputOutputControlByIdentifier",
	[0x31] = "RoutineControl",
	[0x34] = "RequestDownload",
	[0x35] = "RequestUpload",
	[0x36] = "TransferData",
	[0x37] = "TranferExit",
	[0x38] = "RequestFileTransfer",
	[0x3D] = "WriteMemoryByAddress",
	[0x3E] = "TesterPresent",
	[0x83] = "AccessTimingParameter",
	[0x84] = "SecuredDataTransmission",
	[0x85] = "ControlledDTCSetting",
	[0x86] = "ResponseOnEvent",
	[0x87] = "LinkControl"
}

local f_sid_mnemonics = {
	[0x10] = "DSC",
	[0x11] = "ER",
	[0x22] = "RDBI",
	[0x23] = "RMBA",
	[0x24] = "RSDBI",
	[0x25] = "SA",
	[0x28] = "CC",
	[0x29] = "AUTH",
	[0x2A] = "RDBPI",
	[0x2C] = "DDDI",
	[0x2E] = "WDBI",
	[0x2F] = "IOCBI",
	[0x31] = "RC",
	[0x34] = "RD",
	[0x35] = "RU",
	[0x36] = "TD",
	[0x37] = "RTE",
	[0x38] = "RFT",
	[0x3D] = "WMBA",
	[0x3E] = "TP",
	[0x83] = "ATP",
	[0x84] = "SDT",
	[0x85] = "CDTCS",
	[0x86] = "ROE",
	[0x87] = "LC"
}

function get_sid_string(sid)

	-- 0x00..0x09 : ?

	-- 0x10..0x7E : service requests
	if ((sid>=0x1) and (sid<=0x3E)) then
		if (f_sid_strings[sid] ~= nil) then
			return f_sid_strings[sid]
		else
			return "Unknown 0x"..bit.tohex(sid, 2)
		end
	end

	-- 0x3F..0x4F : not applicable 

	-- 0x50..0x7E : positive service responses 
	if ((sid>=0x50) and (sid<=0x7E)) then
		if (f_sid_strings[bit.band(sid, 0xBF)] ~= nil) then
			return f_sid_strings[bit.band(sid, 0xBF)] .. "Response"
		else
			return "Unknown 0x"..bit.tohex(sid, 2) .. "Response"
		end
	end

	-- 0x7F : negative response
	if (sid == 0x7f) then
		return "NegativeResponse"
	end
	
	-- 0x80..0x83 : not applicable
	
	-- 0x83.0x88 : service requests
	if ((sid>=0x83) and (sid<=0x88)) then
		if (f_sid_strings[sid] ~= nil) then
			return f_sid_strings[sid]
		else
			return "Unknown 0x"..bit.tohex(sid, 2)
		end
	end

	-- 0x88..0xBA : not applicable
	-- 0xBA..0xBE : service requests by system supplier
	-- 0xBF..0xC2 : not applicable

	-- 0xC3..0xC8 : positive service responses
	if ((sid>=0xC3) and (sid<=0xC8)) then
		if (f_sid_strings[bit.band(sid, 0xBF)] ~= nil) then
			return f_sid_strings[bit.band(sid, 0xBF)]
		else
			return "Unknown 0x"..bit.tohex(sid, 2)
		end
	end
	
	-- 0xFA..0xFE : positive service responses by system supplier
	
	-- 0xFF : not applicable

	return "Unknown 0x"..bit.tohex(sid, 2)
end

local f_nrc_strings = {
	[0x10] = "General Reject",
	[0x11] = "Service not suppported",
	[0x12] = "Subfunction not supported",
	[0x13] = "Incorrect message length or invalid format",
	[0x14] = "Response too long",
	[0x21] = "Busy, repeat request",
	[0x22] = "Conditions not correct",
	[0x24] = "Request sequence error",
	[0x25] = "No response from subnet component",
	[0x26] = "Failure prevents execution of requested action",
	[0x31] = "Request out of range",
	[0x33] = "Security access denied",
	[0x35] = "Invalid key",
	[0x36] = "Exceed number of attempts",
	[0x37] = "Required time delay not expired",
	[0x38] = "Secure data transmission required",
	[0x39] = "Secure data transmission not allowed",
	[0x3A] = "Secure data verification failed",
	[0x50] = "Certificate validation failed, invalid time period",
	[0x51] = "Certificate validation failed, invalid signature",
	[0x52] = "Certificate validation failed, invalid chain of trust",
	[0x53] = "Certificate validation failed, invalid type",
	[0x54] = "Certificate validation failed, invalid format",
	[0x55] = "Certificate validation failed, invalid content",
	[0x56] = "Certificate validation failed, invalid scope",
	[0x57] = "Certificate validation failed, invalid certificate",
	[0x58] = "Ownership verification failed",
	[0x59] = "Challenge calculation failed",
	[0x5A] = "Setting access right failed",
	[0x5B] = "Session key creation/derivation failed",
	[0x5C] = "Configuration data usage failed",
	[0x5D] = "Deauthentification failed",
	[0x70] = "Upload download not accepted",
	[0x71] = "Transfer data suspended",
	[0x72] = "General programming failure",
	[0x73] = "Wrong block sequence number",
	[0x78] = "Request correctly received, response pending",
	[0x7E] = "Subfunction not supported in active session",
	[0x7F] = "Service not suppported in active session",
	[0x81] = "RPM too high",
	[0x82] = "RPM too low",
	[0x83] = "Engine is running",
	[0x84] = "Engine is not running",
	[0x85] = "Engine run time too low",
	[0x86] = "Temperature too high",
	[0x87] = "Temperature too low",
	[0x88] = "Vehicle speed too high",
	[0x89] = "Vehicle speed too low",
	[0x8A] = "Throttle/pedal too high",
	[0x8B] = "Throttle/pedal too low",
	[0x8C] = "Transmission range not in neutral",
	[0x8D] = "Transmission range not in gear",
	[0x8F] = "Brake switch not closed",
	[0x90] = "Shifter lever not in park",
	[0x91] = "Torque converter clutch locked",
	[0x92] = "Voltage too high",
	[0x93] = "Voltage too low",
	[0x94] = "Resource temporary unavailable"
}

local f_nrc_mnemonics = {
	[0x10] = "GR",
	[0x11] = "SNS",
	[0x12] = "SFNS",
	[0x13] = "IMLOIF",
	[0x14] = "RTL",
	[0x21] = "BRR",
	[0x22] = "CNC",
	[0x24] = "RSE",
	[0x25] = "NRFSC",
	[0x26] = "FPEORA",
	[0x31] = "ROOR",
	[0x33] = "SAD",
	[0x35] = "IK",
	[0x36] = "ENOA",
	[0x37] = "RTDNE",
	[0x38] = "SDTR",
	[0x39] = "SDTNA",
	[0x3A] = "SDVF",
	[0x50] = "CVFITP",
	[0x51] = "CVFIS",
	[0x52] = "CVFICOT",
	[0x53] = "CVFIT",
	[0x54] = "CVFIF",
	[0x55] = "CVFIC",
	[0x56] = "CVFIS",
	[0x57] = "CVFIC",
	[0x58] = "OVF",
	[0x59] = "CCF",
	[0x5A] = "SARF",
	[0x5B] = "SKCDF",
	[0x5C] = "CDUF",
	[0x5D] = "DF",
	[0x70] = "UDNA",
	[0x71] = "TDS",
	[0x72] = "GPF",
	[0x73] = "WBSN",
	[0x78] = "RCRRP",
	[0x7E] = "SFNSIAS",
	[0x7F] = "SNSIAS",
	[0x81] = "RPMTH",
	[0x82] = "RPMTL",
	[0x83] = "EIR",
	[0x84] = "EINR",
	[0x85] = "ERTTL",
	[0x86] = "TEMPTH",
	[0x87] = "TEMPTL",
	[0x88] = "VSTH",
	[0x89] = "VSTL",
	[0x8A] = "TPTH",
	[0x8B] = "TPTL",
	[0x8C] = "TRNIN",
	[0x8D] = "TRNIG",
	[0x8F] = "BSNC",
	[0x90] = "SLNIP",
	[0x91] = "TCCL",
	[0x92] = "VTH",
	[0x93] = "VTL",
	[0x94] = "RTU"
}


function get_nrc_string(sid)

	if (f_nrc_strings[sid] ~= nil) then
		return f_nrc_strings[sid]
	else
		return "Unknown 0x"..bit.tohex(sid, 2)
	end
end

local f_session_type_strings = {
	[0x00] = "ISOAEReserved",
	[0x01] = "DefaultSession",
	[0x02] = "ProgrammingSession",
	[0x03] = "ExtendedProgrammingSession",
	[0x04] = "SafetySystemDiagnosticSession",
	[0x05] = "ISOAEReserved",
	[0x40] = "VehicleManufacturerSpecific",
	[0x60] = "SystemSupplierSpecific",
	[0x7f] = "ISOAEReserved"
}

function get_session_type_string(session_type)
	if f_session_type_strings[session_type] ~= nil then
		return f_session_type_strings[session_type]
	else
		if ((session_type >= 0x05) and (session_type <= 0x3f)) then
			return f_session_type_strings[0x05]
		end
		if ((session_type >= 0x40) and (session_type <= 0x5f)) then
			return f_session_type_strings[0x40]
		end
		if ((session_type >= 0x60) and (session_type <= 0x7e)) then
			return f_session_type_strings[0x60]
		end
		if ((session_type == 0x7f)) then
			return f_session_type_strings[0x7f]
		end
		return "Unknown 0x"..bit.tohex(session_type,2)
	end
end
	
local f_routine_control_subf_strings = {
	[0x00] = "ISOAEReserved",
	[0x01] = "StartRoutine",
	[0x02] = "StopRoutine",
	[0x03] = "RequestRoutineResults",
	[0x04] = "ISOAEReserved",
}

function get_routine_control_subf_string(subf)
	if f_routine_control_subf_strings[subf] ~= nil then
		return f_routine_control_subf_strings[subf]
	else
		if ((subf >= 0x04) and (subf <= 0x7f)) then
			return f_routine_control_subf_strings[0x04]
		end
		return "Unknown 0x"..bit.tohex(subf,2)
	end
end

function p_uds.init()

	uds_stats['id'] = 0
	uds_stats['start'] = 0 
	uds_stats['reqs'] = 0
	uds_stats['bytes'] = 0

	uds_stats['dtool_delay'] = 0
	uds_stats['ecu_delay'] = 0
	uds_stats['dtool_time'] = 0
	uds_stats['ecu_time'] = 0
	uds_stats['last_bsc'] = 0
	uds_stats['last_transfer_data_time'] = 0
	uds_stats['last_transfer_data_response_time'] = 0

	-- lookup dissector 
	result, data_dissector = pcall(Dissector.get, "data")
	if result == false then
		print("Could not find \"data\" dissector")
		data_dissector = nil
	end

end

function p_uds.dissector(buf, info, tree)

	info.cols.protocol = SIGB .. "UDS"	

	local offset = 0
	-- subtree 8 bytes
	local subtree = tree:add(p_uds, buf(offset, buf:len())) -- eat all remaining

	local v_sid = buf(offset, 1):uint();
	if  v_sid == 0x7f then
		-- branch
		local sub_subtree = subtree:add(f_nr_sid, buf(offset, 1))
		info.cols.protocol:append(" " .. get_sid_string(v_sid))
		subtree:append_text(" " .. get_sid_string(v_sid))
		sub_subtree:append_text(" " .. get_sid_string(v_sid))
		offset = offset + 1

		negative_response(buf(offset):tvb(), info, subtree)
		
		return offset;
	end

	-- branch sid
	local sub_subtree = subtree:add(f_sid, buf(offset, 1))
	info.cols.protocol:append(" " .. get_sid_string(v_sid))	
	subtree:append_text(" " .. get_sid_string(v_sid))
	sub_subtree:append_text(" " .. get_sid_string(v_sid))
	offset = offset + 1

	if v_sid == 0x10 then
		session_control(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x22 then
		read_by_identifier(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x27 then
		security_access(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x2e then
		write_by_identifier(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x31 then
		routine_control(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x34 then
		request_download(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x36 then
		transfer_data(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x37 then
		transfer_exit(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x3e then
		tester_present(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x50 then
		session_control_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x62 then
		read_by_identifier_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x6e then
		write_by_identifier_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x67 then
		security_access_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x71 then
		routine_control_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x74 then
		request_download_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x76 then
		transfer_data_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x77 then
		transfer_exit_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x7e then
		tester_present_response(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0x87 then
		link_control(buf(offset):tvb(), info, subtree)
	elseif v_sid == 0xc7 then
		link_control_response(buf(offset):tvb(), info, subtree)
	end

	return offset 
end

function handle_data(prefix, buf, info, tree)
	local offset = 0;
	if (buf:len() == 0) then
		return 0
	end
	if (data_dissector ~= nil) then
		local len = data_dissector:call(buf(offset):tvb(), info, tree)
		offset = offset + len;
	else
		subtree = tree:add(f_diag_data,buf(offset))
		tree:append_text(", " .. prefix .. ": " .. buf(offset))
		offset = offset + buf(offset):len()
	end	
	return offset;
end

function session_control(buf, info, tree)
	local offset = 0
	local subtree = tree:add(f_session_type,buf(offset, 1))
	tree:append_text(" " .. get_session_type_string(buf(offset, 1):uint()))
	subtree:append_text(" " .. get_session_type_string(buf(offset, 1):uint()))
	offset = offset + 1 
	return offset 
end

function session_control_response(buf, info, tree)
	local offset = 0
	local subtree = tree:add(f_session_type,buf(offset, 1))
	tree:append_text(" " .. get_session_type_string(buf(offset, 1):uint()))
	subtree:append_text(" " .. get_session_type_string(buf(offset, 1):uint()))
	offset = offset + 1 
	local subtree = tree:add(f_p2_server_max,buf(offset, 2))
	offset = offset + 2 
	local subtree = tree:add(f_p2_server_max_enh,buf(offset, 2))
	offset = offset + 2 
	return offset 
end

function read_by_identifier(buf, info, tree)
	local offset = 0
	local nr_ids = buf:len() / 2
	tree:append_text(" Id=[")
	for i=0,nr_ids-1,1 do
		local subtree = tree:add(f_id, buf(offset, 2))
		tree:append_text(" 0x" .. bit.tohex(buf(offset, 2):uint(), 4))
		offset = offset + 2
	end
	tree:append_text("]")
	return offset 
end

function read_by_identifier_response(buf, info, tree)
	local offset = 0

	local len = handle_data("DataRecord", buf(offset), info, tree);
	offset = offset + len

	return offset 
end

function write_by_identifier(buf, info, tree)
	local offset = 0
	
	tree:append_text(" Id=0x" .. bit.tohex(buf(offset, 2):uint(), 4))
	local id = buf(offset, 2)
	local subtree = tree:add(f_id, buf(offset, 2))
	offset = offset + 2 
	
	local len = handle_data("DataRecord", buf(offset), info, tree);
	offset = offset + len
	
	return offset 
end

function write_by_identifier_response(buf, info, tree)
	local offset = 0
	return offset 
end

function security_access(buf, info, tree)
	local offset = 0

	local subf = buf(offset, 1):uint()
	local subtree = tree:add(f_subf, subf)
	offset = offset + 1 

	if (bit.band(subf, 0x01) == 0x01) then
		tree:append_text(" RequestSeed(0x" .. bit.tohex(subf, 2)..")")
		subtree:append_text(" RequestSeed")
		local len = handle_data("Seed", buf(offset), info, tree)
		offset = offset + len
	else
		tree:append_text(" SendKey(0x" .. bit.tohex(subf, 2)..")")
		subtree:append_text(" SendKey")
		local len = handle_data("Key", buf(offset), info, tree)
		offset = offset + len
	end
	
	return offset 
end

function security_access_response(buf, info, tree)
	local offset = 0

	local subf = buf(offset, 1):uint()
	local subtree = tree:add(f_subf, subf)
	offset = offset + 1 

	if (bit.band(subf, 0x01) == 0x01) then
		tree:append_text(" RequestSeed(0x" .. bit.tohex(subf, 2)..")")
		subtree:append_text(" RequestSeed")
		local len = handle_data("Seed", buf(offset), info, tree)
		offset = offset + len
	else
		tree:append_text(" SendKey(0x" .. bit.tohex(subf, 2)..")")
		subtree:append_text(" SendKey")
		local len = handle_data("Key", buf(offset), info, tree)
		offset = offset + len
	end

	return offset 
end

function routine_control(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_subf, buf(offset, 1))
	local subf = buf(offset, 1):uint();
	tree:append_text(" " .. get_routine_control_subf_string(subf));
	subtree:append_text(" " .. get_routine_control_subf_string(subf));
	offset = offset + 1 

	local subtree = tree:add(f_id, buf(offset, 2))
	tree:append_text(" Id=0x" .. bit.tohex(buf(offset, 2):uint(), 4))
	offset = offset + 2 

	local len = handle_data("OptionRecord", buf(offset), info, tree)
	offset = offset + len
	
	return offset 
end

function routine_control_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_subf, buf(offset, 1))
	local subf = buf(offset, 1):uint();
	tree:append_text(" " .. get_routine_control_subf_string(subf));
	subtree:append_text(" " .. get_routine_control_subf_string(subf));
	offset = offset + 1 


	local subtree = tree:add(f_id, buf(offset, 2))
	tree:append_text(" Id=0x" .. bit.tohex(buf(offset, 2):uint(), 4))
	offset = offset + 2 

	local len = handle_data("StatusRecord", buf(offset), info, tree)
	offset = offset + len
	
	return offset 
end


function request_download(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_dfi, buf(offset, 1))
	tree:append_text(" dfi=0x" .. bit.tohex(buf(offset, 1):uint(), 2))
	offset = offset + 1 

	local subtree = tree:add(f_alfid,buf(offset, 1))
	local addr_format = bit.band(buf(offset, 1):uint(), 0x0F)
	local length_format = bit.rshift(buf(offset, 1):uint(), 4)
	tree:append_text(" alfid=0x" .. bit.tohex(buf(offset, 1):uint(), 2))
	offset = offset + 1 

	local addr = 0
	if addr_format > 0 then
		addr = buf(offset, addr_format):uint()
		local subtree = tree:add(f_addr, buf(offset, addr_format))
		tree:append_text(" Addr=0x" .. bit.tohex(buf(offset, addr_format):uint(), addr_format*2))
		offset = offset + addr_format
	end
	local length = 0
	if length_format > 0 then
		length = buf(offset, length_format):uint()
		local subtree = tree:add(f_length, buf(offset, length_format))
		tree:append_text(" Length=0x" .. bit.tohex(buf(offset, length_format):uint(), length_format*2))
		offset = offset + length_format
	end

	if (not info.visited) then
		uds_stats['id'] = uds_stats['id'] + 1 
		uds_stats['start'] = info.abs_ts
		uds_stats['reqs'] = 0
		uds_stats['bytes'] = 0
	
		uds_stats['dtool_delay'] = 0
		uds_stats['ecu_delay'] = 0
		uds_stats['dtool_time'] = 0
		uds_stats['ecu_time'] = 0
		uds_stats['last_bsc'] = 0
		uds_stats['last_transfer_data_time'] = 0
		uds_stats['last_transfer_data_response_time'] = 0

		uds_stats[info.number] = {['id'] = uds_stats['id'] } 
	end
	
	tree:append_text(" Stats: Id=" .. uds_stats[info.number]['id'])
		
	local statsTree = tree:add("Stats")
	statsTree:add("id: " .. uds_stats[info.number]['id'])

	info.cols.protocol:append(" stats{id=" .. uds_stats[info.number]['id'] .. "}")
	
	return offset 
end

function request_download_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_lfid, buf(offset, 1))
	local length_format = bit.rshift(buf(offset, 1):uint(), 4)
	offset = offset + 1 

	local max_block_length = 0
	if length_format > 0 then
		max_block_length = buf(offset, length_format):uint()
		local subtree = tree:add(f_max_block_length, buf(offset, length_format))
		tree:append_text(" MaxBlockLength=" .. max_block_length)
		offset = offset + length_format
	end

	return offset 
end

function transfer_data(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_bsc, buf(offset, 1))
	local bsc = buf(offset, 1):uint()
	offset = offset + 1 
	local len = buf(offset):len()

	if (not info.visited) then
	
		-- increment
		uds_stats['reqs'] = uds_stats['reqs'] + 1 
		uds_stats['bytes'] = uds_stats['bytes'] + len
		if uds_stats['last_transfer_data_response_time'] ~= 0 then -- first transferdata 
			uds_stats['dtool_delay'] = (info.abs_ts - uds_stats['last_transfer_data_response_time'])
			uds_stats['dtool_time'] = uds_stats['dtool_time'] + uds_stats['dtool_delay']
		end
		
		-- update
		uds_stats['last_bsc'] = bsc 
		uds_stats['last_transfer_data_time'] = info.abs_ts

		uds_stats[info.number] = {
			['id'] = uds_stats['id'],
			['reqs'] = uds_stats['reqs'],
			['bytes'] = uds_stats['bytes'],
			['last_transfer_data_time'] = uds_stats['last_transfer_data_time'],
			['last_transfer_data_response_time'] = uds_stats['last_transfer_data_response_time'],
			['dtool_delay'] = uds_stats['dtool_delay'],
			['ecu_delay'] = uds_stats['ecu_delay'],
			['dtool_time'] = uds_stats['dtool_time'],
			['ecu_time'] = uds_stats['ecu_time']
		} 
	end
	
	tree:append_text(" Bsc=" .. bsc)
	tree:append_text(" Length=" .. len)
	tree:append_text(" Stats: Id=" .. uds_stats[info.number]['id'])
	tree:append_text(" Reqs=" .. uds_stats[info.number]['reqs'])
	tree:append_text(" Bytes=" .. uds_stats[info.number]['bytes'])
	tree:append_text(" DTool_time=" .. uds_stats[info.number]['dtool_time'])
	tree:append_text(" ECU_time=" .. uds_stats[info.number]['ecu_time'])
	
	local statsTree = tree:add("Stats")
	statsTree:add("id: " .. uds_stats[info.number]['id'])
	statsTree:add("reqs: " .. uds_stats[info.number]['reqs'])
	statsTree:add("bytes: " .. uds_stats[info.number]['bytes'])
	statsTree:add("dtool_delay: " .. uds_stats[info.number]['dtool_delay'])
	statsTree:add("ecu_delay: " .. uds_stats[info.number]['ecu_delay'])
	statsTree:add("dtool_time: " .. uds_stats[info.number]['dtool_time'])
	statsTree:add("ecu_time: " .. uds_stats[info.number]['ecu_time'])
	
	info.cols.protocol:append(" bsc=" .. bsc .. " len=" .. len .. " stats{id=" .. uds_stats[info.number]['id'] .. " reqs=" .. uds_stats[info.number]['reqs'] .. " bytes=" .. uds_stats[info.number]['bytes'] .. "}")
	
	local len = handle_data("Data", buf(offset), info, tree)
	offset = offset + len

	return offset 
end

function transfer_data_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_bsc, buf(offset, 1))
	local bsc = buf(offset, 1):uint()
	tree:append_text(" Bsc=" .. bsc)
	offset = offset + 1 
	
	if (not info.visited) then
	
		-- increment
		if uds_stats['last_transfer_data_time'] ~= 0 then -- first transferdataresponse 
			uds_stats['ecu_delay'] = info.abs_ts - uds_stats['last_transfer_data_time']
			uds_stats['ecu_time'] = uds_stats['ecu_time'] + uds_stats['ecu_delay']
		end
		
		-- update
		uds_stats['last_transfer_data_response_time'] = info.abs_ts

		uds_stats[info.number] = {
			['id'] = uds_stats['id'],
			['reqs'] = uds_stats['reqs'],
			['bytes'] = uds_stats['bytes'],
			['dtool_time'] = uds_stats['dtool_time'],
			['ecu_time'] = uds_stats['ecu_time']
		} 
	end
	
	info.cols.protocol:append("Response" .. " bsc=" .. bsc)

	local len = handle_data("Data", buf(offset), info, tree)
	offset = offset + len

	return offset 
end

function transfer_exit(buf, info, tree)
	local offset = 0

	local len = handle_data("Data", buf(offset), info, tree)
	offset = offset + len

	if (not info.visited) then
	
		uds_stats['stop'] = info.abs_ts
		uds_stats[info.number] = {
			['id'] = uds_stats['id'],
			['reqs'] = uds_stats['reqs'],
			['bytes'] = uds_stats['bytes'],
			['start'] = uds_stats['start'],
			['stop'] = uds_stats['stop'],
			['dtool_time'] = uds_stats['dtool_time'],
			['ecu_time'] = uds_stats['ecu_time']
		} 
	end

	local interval = uds_stats[info.number]['stop'] - uds_stats[info.number]['start']
	local delay = interval / uds_stats[info.number]['reqs']
	local bandwidth = math.floor(uds_stats[info.number]['bytes'] / interval)
	local load = math.floor(uds_stats[info.number]['bytes'] / uds_stats[info.number]['reqs'])
	tree:append_text(" Stats: Id=" .. uds_stats[info.number]['id'])
	tree:append_text(" Reqs=" .. uds_stats[info.number]['reqs'])
	tree:append_text(" Bytes=" .. uds_stats[info.number]['bytes'])
	tree:append_text(" Interval=" .. tostring(interval) .. " s")
	tree:append_text(" DTool_time=" .. tostring(uds_stats[info.number]['dtool_time']) .. " s")
	tree:append_text(" ECU_time=" .. tostring(uds_stats[info.number]['ecu_time']) .. " s")
	
	local statsTree = tree:add("Stats")
	statsTree:add("id: " .. uds_stats[info.number]['id'])
	statsTree:add("reqs: " .. uds_stats[info.number]['reqs'])
	statsTree:add("payload: " .. uds_stats[info.number]['bytes'] .. " bytes")
	statsTree:add("interval: " .. tostring(interval) .. " s")
	statsTree:add("dtool_time: " .. tostring(uds_stats[info.number]['dtool_time']) .. " s")
	statsTree:add("ecu_time: " .. tostring(uds_stats[info.number]['ecu_time']) .. " s")
	statsTree:add("avg load: " .. tostring(load) .. " bytes/req")
	statsTree:add("avg delay: " .. tostring(delay) .. " s/req")
	statsTree:add("avg_dtool_delay: " .. tostring(uds_stats[info.number]['dtool_time']/uds_stats[info.number]['reqs']) .. " s")
	statsTree:add("avg_ecu_delay: " .. tostring(uds_stats[info.number]['ecu_time']/uds_stats[info.number]['reqs']) .. " s")
	statsTree:add("avg bandwidth: " .. tostring(bandwidth) .. " bytes/s")
--	statsTree:add("start: " .. format_time(uds_stats[info.number]['start']))
--	statsTree:add("stop: " .. format_time(uds_stats[info.number]['stop']))
	
	info.cols.protocol:append(" stats{id=" .. uds_stats[info.number]['id'] .. " reqs=" .. uds_stats[info.number]['reqs'] .. " bytes=" .. uds_stats[info.number]['bytes'] .. " interval=" .. tostring(interval) .. " s}")
	return offset 
end

function transfer_exit_response(buf, info, tree)
	local offset = 0

	local len = handle_data("Data", buf(offset), info, tree)
	offset = offset + len

	return offset 
end

function tester_present(buf, info, tree)
	local offset = 0
	local subtree = tree:add(f_subf, buf(offset, 1))
	local subf = buf(offset, 1):uint()
	subf = bit.band(subf, 0x7f)
	tree:append_text(" Subf=0x" .. bit.tohex(subf, 2))
	if (bit.band(subf, 0x80) == 0x80) then
		tree:append_text(" SupprPosResponse")
		subtree:append_text(" SupprPosResponse")
	end
	offset = offset + 1 
	
	return offset 
end

function tester_present_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_subf, buf(offset, 1))
	local subf = buf(offset, 1):uint();
	subf = bit.band(subf, 0x7f)
	tree:append_text(" Subf=0x" .. bit.tohex(subf, 2))
	if (bit.band(subf, 0x80) == 0x80) then
		tree:append_text(" SupprPosResponse")
		subtree:append_text(" SupprPosResponse")
	end
	offset = offset + 1 
	return offset 
end

function link_control(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_subf, buf(offset, 1))
	local subtree = tree:add(f_suppr, buf(offset, 1))

	local subf = buf(offset, 1):uint();
	tree:append_text(" Subf=0x" .. bit.tohex(subf, 2))
	offset = offset + 1 
		
	if (subf == 1) then
		tree:append_text(" VerifyModeTransitionWithFixedParameter")
	elseif (subf == 2) then
		tree:append_text(" VerifyModeTransitionWithSpecificParameter")
	elseif (subf == 3) then
		tree:append_text(" TransitionMode")
	else
		tree:append_text(" Unknown")
	end
	return offset 
end

function link_control_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_subf, buf(offset, 1))
	local subf = buf(offset, 1):uint();
	tree:append_text(" Subf=0x" .. bit.tohex(subf, 2))
	offset = offset + 1 
	
	if (subf == 1) then
		tree:append_text(" VerifyModeTransitionWithFixedParameter")
		local subtree = tree:add(f_link_control_mode_identifier, buf(offset, 1))
		tree:append_text(" LinkControlModeIdentifier=0x" .. bit.tohex(buf(offset, 1):uint(), 2))
		offset = offset + 1 
	elseif (subf == 2) then
		tree:append_text(" VerifyModeTransitionWithSpecificParameter")
		local subtree = tree:add(f_link_record, buf(offset, 3))
		tree:append_text(" LinkControlRecord=0x" .. bit.tohex(buf(offset, 3):uint(), 6))
		offset = offset + 1 
	elseif (subf == 3) then
		tree:append_text(" TransitionMode")
	else
		tree:append_text(" Unknown")
	end

	return offset 
end

function negative_response(buf, info, tree)
	local offset = 0

	local subtree = tree:add(f_sid, buf(offset, 1))
	local v_sid = buf(offset, 1):uint()
	subtree:append_text(" " .. get_sid_string(v_sid))
	offset = offset + 1 
	
	local subtree = tree:add(f_nrc, buf(offset, 1))
	local v_nrc = buf(offset, 1):uint()
	tree:append_text(" NRC=0x" .. bit.tohex(v_nrc, 2) .. " "..get_nrc_string(v_nrc))
	subtree:append_text(" " .. get_nrc_string(v_nrc))
	offset = offset + 1 

	info.cols.protocol =  SIGB .. "UDS NRC=0x" .. bit.tohex(v_nrc, 2) .." ".. get_nrc_string(v_nrc)
	
	return offset 
end

