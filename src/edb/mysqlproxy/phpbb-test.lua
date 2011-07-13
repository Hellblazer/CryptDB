assert(package.loadlib("/home/kis/EncryptDB/mysqlproxy/libglobals.so","luaopen_globals"))()

x = 0

function connect_server()
	print("***")
	x = x + 1;
	globals.mine(x)
	globals.set_value(1)
end

function E(w)
	w = string.gsub(w,"%a",globals.enc)
	return "VALUES"..w
end

function D(w)
	w = string.gsub(w,"%a",globals.dec)
	w = string.gsub(w,"{",globals.dec)	
	return w
end

function read_query( packet )
	print(globals.get_i())
	if string.byte(packet) == proxy.COM_QUERY then
		print("we got a normal query: " .. string.sub(packet, 2))
		local query = string.sub(packet, 2)
		local replacing = false
		if string.match(string.upper(query), 'VALUES') then
		   local new_query = query
		   new_query = string.gsub(new_query,'VALUES(.*)', E)
		   print("  query changed to: " .. new_query)
		   local num = globals.get_num()
		   print("  this is the " .. num .. "th character we messed with")
                   proxy.queries:append(2, string.char(proxy.COM_QUERY) .. query, { resultset_is_needed = true } )
       		   replacing = true
     		end
		if string.match(query, 'SELECT') and not string.match(string.upper(query), 'DATABASE') then
                   proxy.queries:append(3, string.char(proxy.COM_QUERY) .. query, { resultset_is_needed = true } )
		   replacing = true
		end
		if replacing then
		   return proxy.PROXY_SEND_QUERY
		end
	end
end

function read_query_result(inj)
	local res = assert(inj.resultset)
	print("  injected result-set: id = " .. inj.id)
	if (res) and (inj.id == 3) then
	   	local row_return = {}
		for row in res.rows do
			-- print("    injected query returned: " .. row[1]-1)
			local j = 1
			local new_row = {}
			while row[j] ~= nil do			      
			      --table.insert(new_row, D(row[j]))
			      table.insert(new_row, row[j])
			      j = j + 1
			end
			table.insert(row_return,new_row)
		end

		local field_return = {}
		local i = 1
		while res.fields[i] do
		      table.insert(field_return, { type=res.fields[i].type, name=res.fields[i].name})
		      i = i + 1
		end

		local current_type = inj.type
		proxy.response.type = proxy.MYSQLD_PACKET_OK

		proxy.response.resultset = {
				fields = field_return ,
				rows =  row_return  }

		--proxy.response.resultset = res
		return proxy.PROXY_SEND_RESULT	
	end
end
