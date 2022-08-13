function string:endswith(ending)
    return ending == "" or self:sub(-#ending) == ending
end

do
	local http_wrapper_proto = Proto("http_resp", "Upstream HTTP request")
	local http_extra_proto = Proto("xblive-matchmaking", "Xbox Live Matchmaking")

	local stream_map = {}  -- a table per each stream : { req_cnt, resp_cnt, reqs }
	local resp_map = {}    -- a table mapping responses to requests

	-- added for responses
	http_wrapper_proto.fields.re_req_method = ProtoField.string("http_resp.request.method", "Request Method")
	http_wrapper_proto.fields.re_req_uri    = ProtoField.string("http_resp.request.uri", "Request URI")
	http_wrapper_proto.fields.re_req_ver    = ProtoField.string("http_resp.request.version", "Request Version")
	http_wrapper_proto.fields.re_host       = ProtoField.string("http_resp.host", "Host")

	-- added for requests and responses
	http_extra_proto.fields.URL             = ProtoField.string("http.request.URL", "Request URL")

	local f_req_meth    = Field.new("http.request.method")
	local f_req_uri     = Field.new("http.request.uri")
	local f_req_ver     = Field.new("http.request.version")
	local f_req_host    = Field.new("http.host")
	local f_resp_code   = Field.new("http.response.code")
	local f_tcp_stream  = Field.new("tcp.stream")
	local f_tcp_dstport = Field.new("tcp.dstport")
	local f_tcp_srcport = Field.new("tcp.srcport")
	local f_ip_dsthost  = Field.new("ip.dst_host")
	local f_ip_srchost  = Field.new("ip.src_host")

	function http_wrapper_proto.init()
		stream_map = {}
		resp_map = {}
	end

	local function optional_port(tcp_port)
		if tcp_port ~= 443 and tcp_port ~= 80 then
			return ":" .. tcp_port
		end
		return ""
	end

	local function scheme_by_port(tcp_port)
		if tcp_port == 443 then
			return "https://"
		else
			return "http://"
		end
	end

	function http_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
		if not f_tcp_stream() then return end

		local stream_n
		local URL

		stream_n = f_tcp_stream().value
		URL = nil

		-- when we meet request first time, add it to the stream_map and bump global requests counter 
		if f_req_meth() then
			tcp_port = f_tcp_dstport().value
			local host
			if f_req_host() then
				host = f_req_host().value
			else
				host = f_ip_dsthost().value
			end
			URL = scheme_by_port (tcp_port) .. host .. optional_port(tcp_port) .. f_req_uri().value

			if not pinfo.visited then
				if stream_map[stream_n] == nil then
					stream_map[stream_n] = {0,0,{}}
				end

				-- bump incoming requests count
				request_n = stream_map[stream_n][1] + 1
				stream_map[stream_n][1] = request_n

				stream_map[stream_n][3][ request_n ] = {f_req_meth().value, f_req_uri().value, f_req_ver().value, f_req_host().value}
			end
		end

		-- when we meet response, we lookup bump stream responses counter and map it to the corresponding request
		if f_resp_code() then
			local response_n
			if not pinfo.visited then
				if not stream_map[stream_n] then
					warn("HTTP response not in stream (" .. pinfo.number .. ")")
					response_n = 0
				else
					response_n = stream_map[stream_n][2] + 1
					stream_map[stream_n][2] = response_n
					resp_map[pinfo.number] = response_n
				end
			else
				response_n = resp_map[pinfo.number]
			end

			tcp_port = f_tcp_srcport().value
			if response_n > 0 then
				local subtree = treeitem:add(http_wrapper_proto, nil)
				local data = stream_map[stream_n][3][response_n]
				if data then
					subtree:add(http_wrapper_proto.fields.re_req_method, data[1]):set_generated()
					subtree:add(http_wrapper_proto.fields.re_req_uri, data[2]):set_generated()
					subtree:add(http_wrapper_proto.fields.re_req_ver, data[3]):set_generated()
					if (data[4]) then
						subtree:add(http_wrapper_proto.fields.re_host, data[4]):set_generated()
					end

					host = data[4]
					if not host then
						host = f_ip_srchost().value
					end

					URL = scheme_by_port(tcp_port) .. host .. optional_port(tcp_port) .. data[2]
				else
					warn("HTTP request data lost (" .. stream_n .. "," .. response_n .. ")")
				end
			end
		end

		if URL and URL:endswith("/xmatch/xmatchclient.srf") then
			local extratree = treeitem:add(http_extra_proto, nil)
			extratree:add(http_extra_proto.fields.URL, URL):set_generated()
		end
	end

	register_postdissector(http_wrapper_proto)
end
