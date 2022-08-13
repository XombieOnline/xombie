do
	local presence_proto = Proto("xblive-presence", "XBox Live Presence")

	-- BASE_MSG_HEADER
	local msg_type_field = ProtoField.uint32("presence.msgType", "Message Type")
	local msg_len_field = ProtoField.uint32("presence.msgLen", "Message Length")
	local seq_num_field = ProtoField.uint32("presence.seqNum", "Sequence Number")
	local sg_addr_ina_sg_field = ProtoField.ipv4("presence.sgAddr.inaSg", "SG Address")
	local sg_addr_spi_sg_field = ProtoField.uint24("presence.sgAddr.spiSg", "SG SPI", base.HEX)
	local sg_addr_xbox_id_field = ProtoField.uint64("presence.sgAddr.xboxID", "Xbox ID", base.HEX)
	local sg_addr_reserved_field = ProtoField.bytes("presence.sgAddr.reserved", "Reserved")

	-- P_ALIVE_MSG
	local alive_user_id_field = ProtoField.uint64("presence.alive.user_id", "User ID", base.HEX)
	local alive_title_id = ProtoField.uint32("presence.alive.title_id", "Title ID", base.HEX)
	local alive_acct_name_len = ProtoField.uint16("presence.alive.acct_name_len", "Account Name Len")
	local alive_buddy_list_version = ProtoField.uint32("presence.alive.buddy_list_version", "Buddy List Version")
	local alive_block_list_version = ProtoField.uint32("presence.alive.block_list_version", "Block List Version")
	local alive_state = ProtoField.uint32("presence.alive.state", "State")
	local alive_match_session_id = ProtoField.uint64("presence.alive.match_session_id", "Match Session ID", base.HEX)
	local alive_nickname_len = ProtoField.uint16("presence.alive.nickname_len")
	local alive_title_stuff_len = ProtoField.uint16("presence.alive.title_stuff_len")
	local alive_acct_name = ProtoField.stringz("presence.alive.acct_name", "Account Name")

	-- P_ALIVE_2_MSG
	local alive_2_user_id_field = ProtoField.uint64("presence.alive_2.user_id", "User ID", base.HEX)
	local alive_2_acct_name_len = ProtoField.uint16("presence.alive_2.acct_name_len", "Account Name Len")
	local alive_2_xnaddr_ina = ProtoField.ipv4("presence.alive_2.xnaddr.ipa", "Xbox SG IP")
	local alive_2_xnaddr_ina_online = ProtoField.ipv4("presence.alive_2.xnaddr.ipa_online", "Xbox Public IP")
	local alive_2_xnaddr_port_online = ProtoField.uint16("presence.alive_2.xnaddr.port_online", "Xbox Public Port")
	local alive_2_xnaddr_enet = ProtoField.ether("presence.alive_2.xnaddr.enet", "Xbox MAC Address")
	local alive_2_xnaddr_online = ProtoField.bytes("presence.alive_2.xnaddr.online", "abOnline")
	local alive_2_xnkid = ProtoField.bytes("presence.alive_2.xnkid", "XNKID")
	local alive_2_xnkey = ProtoField.bytes("presence.alive_2.xnkey", "XNKEY")
	local alive_2_buddy_list_version = ProtoField.uint32("presence.alive_2.buddy_list_version", "Buddy List Version")
	local alive_2_block_list_version = ProtoField.uint32("presence.alive_2.block_list_version", "Block List Version")
	local alive_2_client_ver_major = ProtoField.uint16("presence.alive_2.client_ver.major", "Major")
	local alive_2_client_ver_minor = ProtoField.uint16("presence.alive_2.client_ver.minor", "Minor")
	local alive_2_client_ver_build = ProtoField.uint16("presence.alive_2.client_ver.build", "Build")
	local alive_2_client_ver_qfe = ProtoField.uint16("presence.alive_2.client_ver.qfe", "QFE")
	local alive_2_title_id = ProtoField.uint32("presence.alive_2.title_id", "Title ID", base.HEX)
	local alive_2_title_version = ProtoField.uint32("presence.alive_2.title_version", "Title Version", base.HEX)
	local alive_2_title_region = ProtoField.uint32("presence.alive_2.title_region", "Title Region")
	local alive_2_ipportl = ProtoField.uint16("presence.alive_2.ipportl", "ipportl")
	local alive_2_ipal = ProtoField.ipv4("presence.alive_2.ipal", "ipal")
	local alive_2_nonce = ProtoField.uint64("presence.alive_2.nonce", "Nonce", base.HEX)
	local alive_2_time_init = ProtoField.uint64("presence.alive_2.time_init", "Time Init")
	local alive_2_acct_name = ProtoField.stringz("presence.alive_2.acct_name", "Account Name")

	-- P_ALIVE_REPLY_MSG
	local alive_reply_hr = ProtoField.uint32("presence.alive_reply.hr", "HRESULT", base.HEX)
	local alive_reply_buddy_list_version = ProtoField.uint32("presence.alive_reply.buddy_list_version", "Buddy List Version")
	local alive_reply_buddies_sent = ProtoField.uint16("presence.alive_reply.buddies_sent", "Buddies Sent")
	local alive_reply_block_list_version = ProtoField.uint32("presence.alive_reply.block_list_version", "Block List Version")
	local alive_reply_blocks_sent = ProtoField.uint16("presence.alive_reply.blocks_sent", "Blocks Sent")

	presence_proto.fields = {
		-- BASE_MSG_HEADER
		msg_type_field,
		msg_len_field,
		seq_num_field,
		sg_addr_ina_sg_field,
		sg_addr_spi_sg_field,
		sg_addr_xbox_id_field,
		sg_addr_reserved_field,

		-- P_ALIVE_MSG (1001)
		alive_user_id_field,
		alive_title_id,
		alive_acct_name_len,
		alive_buddy_list_version,
		alive_block_list_version,
		alive_state,
		alive_match_session_id,
		alive_nickname_len,
		alive_title_stuff_len,
		alive_acct_name,

		-- P_ALIVE_2_MSG (1025)
		alive_2_acct_name_len,
		alive_2_user_id_field,
		alive_2_xnaddr_ina,
		alive_2_xnaddr_ina_online,
		alive_2_xnaddr_port_online,
		alive_2_xnaddr_enet,
		alive_2_xnaddr_online,
		alive_2_xnkid,
		alive_2_xnkey,
		alive_2_buddy_list_version,
		alive_2_block_list_version,
		alive_2_client_ver_major,
		alive_2_client_ver_minor,
		alive_2_client_ver_build,
		alive_2_client_ver_qfe,
		alive_2_title_id,
		alive_2_title_version,
		alive_2_title_region,
		alive_2_ipportl,
		alive_2_ipal,
		alive_2_nonce,
		alive_2_time_init,
		alive_2_acct_name,

		-- P_ALIVE_REPLY_MSG (1101)
		alive_reply_hr,
		alive_reply_buddy_list_version,
		alive_reply_buddies_sent,
		alive_reply_block_list_version,
		alive_reply_blocks_sent,
	};

	local P_ALIVE_MSG_TYPE       = 1001
	local P_ALIVE_2_MSG_TYPE     = 1025
	local P_ALIVE_REPLY_MSG_TYPE = 1101

	local msg_type_names = {}
	msg_type_names[P_ALIVE_MSG_TYPE]       = "P_ALIVE_MSG"
	msg_type_names[P_ALIVE_2_MSG_TYPE]     = "P_ALIVE_2_MSG"
	msg_type_names[P_ALIVE_REPLY_MSG_TYPE] = "P_ALIVE_REPLY_MSG"

	local function compute_msg_type_name(msg_type)
		if msg_type_names[msg_type] ~= nil then
			return msg_type_names[msg_type]
		end

		return string.format("<Unknown Msg Type %d>", msg_type)
	end

	local function p_alive_dissector(tvb,pkt,root)
		root:add_le(alive_user_id_field, tvb(0,8))
		root:add_le(alive_title_id, tvb(8,4))
		root:add_le(alive_acct_name_len, tvb(12,2))
		root:add_le(alive_buddy_list_version, tvb(14,4))
		root:add_le(alive_block_list_version, tvb(18,4))
		root:add_le(alive_state, tvb(22,4))
		root:add_le(alive_match_session_id, tvb(26,8))
		root:add_le(alive_nickname_len, tvb(34,2))
		root:add_le(alive_title_stuff_len, tvb(36,2))
		root:add(alive_2_acct_name, tvb(38))
	end

	local function p_alive_2_dissector(tvb,pkt,root)
		root:add_le(alive_2_user_id_field, tvb(0,8))
		root:add_le(alive_2_acct_name_len, tvb(8,2))
		local xnaddr_tree = root:add(tvb(10,36), "XNADDR")
		xnaddr_tree:add(alive_2_xnaddr_ina, tvb(10,4))
		xnaddr_tree:add(alive_2_xnaddr_ina_online, tvb(14,4))
		xnaddr_tree:add_le(alive_2_xnaddr_port_online, tvb(18,2))
		xnaddr_tree:add(alive_2_xnaddr_enet, tvb(20,6))
		xnaddr_tree:add(alive_2_xnaddr_online, tvb(26,20))
		root:add(alive_2_xnkid, tvb(46,8))
		root:add(alive_2_xnkey, tvb(54,16))
		root:add_le(alive_2_buddy_list_version, tvb(70,4))
		root:add_le(alive_2_block_list_version, tvb(74,4))
		local client_ver_tree = root:add(tvb(78,8), "Client Version")
		client_ver_tree:add_le(alive_2_client_ver_major, tvb(78,2))
		client_ver_tree:add_le(alive_2_client_ver_minor, tvb(80,2))
		client_ver_tree:add_le(alive_2_client_ver_build, tvb(82,2))
		client_ver_tree:add_le(alive_2_client_ver_qfe, tvb(84,2))
		root:add_le(alive_2_title_id, tvb(86,4))
		root:add_le(alive_2_title_version, tvb(90,4))
		root:add_le(alive_2_title_region, tvb(94,4))
		root:add_le(alive_2_ipportl, tvb(98,2))
		root:add(alive_2_ipal, tvb(100,4))
		root:add_le(alive_2_nonce, tvb(104,8))
		root:add_le(alive_2_time_init, tvb(112,8))
		root:add(alive_2_acct_name, tvb(120))
	end

	local function p_alive_reply_dissector(tvb,pkt,root)
		root:add_le(alive_reply_hr, tvb(0,4))
		root:add_le(alive_reply_buddy_list_version, tvb(4,4))
		root:add_le(alive_reply_buddies_sent, tvb(8,2))
		root:add_le(alive_reply_block_list_version, tvb(10,4))
		root:add_le(alive_reply_blocks_sent, tvb(14,2))
	end

	local dissectors = {}
	dissectors[P_ALIVE_MSG_TYPE]       = p_alive_dissector
	dissectors[P_ALIVE_2_MSG_TYPE]     = p_alive_2_dissector
	dissectors[P_ALIVE_REPLY_MSG_TYPE] = p_alive_reply_dissector

	local function presence_dissector(tvb,pkt,root)
		pkt.cols.protocol = "XBLive Presence"
		local main_tree = root:add(presence_proto, tvb())
		local msg_type = tvb(0,4):le_uint()
		local msg_type_name = compute_msg_type_name(msg_type)
		local prev_info = pkt.cols.info
		pkt.cols.info = string.format("%s %s", msg_type_name, prev_info)
		main_tree:add_le(msg_type_field, tvb(0,4), msg_type, string.format("Message Type: %s (%d)", msg_type_name, msg_type))
		main_tree:add_le(msg_len_field, tvb(4,4))
		main_tree:add_le(seq_num_field, tvb(8,4))
		main_tree:add(sg_addr_ina_sg_field, tvb(12,4))
		main_tree:add_le(sg_addr_spi_sg_field, tvb(17,3))
		main_tree:add_le(sg_addr_xbox_id_field, tvb(20,8))
		main_tree:add(sg_addr_reserved_field, tvb(28,4))

		if dissectors[msg_type] ~= nil then
			local msg_tree = root:add(tvb(32), msg_type_name)
			dissectors[msg_type](tvb(32), pkt, msg_tree)
		end

		return true
	end

	function presence_proto.dissector(tvb,pkt,root)
		if not presence_dissector(tvb,pkt,root) then
			data_dis:call(tvb,pkt,root)
		end
	end

	local tbl = DissectorTable.get("media_type")
	tbl:add("xon/1", presence_proto)
end
