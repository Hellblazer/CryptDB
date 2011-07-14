assert(package.loadlib("/home/kis/EncryptDB/mysqlproxy/libresultset.so","luaopen_resultset"))()

x = 0

function connect_server()
	x = x + 1;
end

function unmarshallBinary(b)
	local k = 3
	local bin = ""
	while k < b:len() do
--TODO
	end	      
end

function marshallBinary(w)
	local ls={w:byte(1,w:len())}
	local k = 1
	local str = ""
	while k <= w:len() do
	      local temp = string.format("%X",ls[k])
	      if (temp:len() == 1) then
	      	 temp = "0" .. temp
	      end
	      str = str .. temp
	      k = k + 1
	end
	return "x\'"..str.."\'"	
end
	

function read_query( packet )
	if string.byte(packet) == proxy.COM_QUERY then
		print("we got a normal query: " .. string.sub(packet, 2))
		local query = string.sub(packet, 2)
		local replacing = false
		if string.match(string.upper(query), 'VALUES') then
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
	-- id is 3 when query was SELECT... we expect a response
	if (res) and (inj.id == 3) then
		local field_return = {}
		local i = 1
		local isblob = {}
		while res.fields[i] do
		      table.insert(field_return, { type=res.fields[i].type, name=res.fields[i].name})
		      if (res.fields[i].type == proxy.MYSQL_TYPE_BLOB ) then
		      	 print(res.fields[i].name.." is blob")
		      	 table.insert(isblob,"true")
		      else
			 table.insert(isblob,"false")
		      end 
		      if (res.fields[i].type == proxy.MYSQL_TYPE_VAR_STRING) then
		      	 print(res.fields[i].name.." is var string")
		      end
		      if (res.fields[i].type == proxy.MYSQL_TYPE_STRING) then
		      	 print(res.fields[i].name.." is string")
		      end
		      i = i + 1
		end

	   	local row_return = {}
		for row in res.rows do
			-- print("    injected query returned: " .. row[1]-1)
			local j = 1
			local new_row = {}
			while row[j] ~= nil do
			      if (isblob[j]=="true") then
			      	 row[j] = marshallBinary(row[j])
			      end
			      table.insert(new_row, row[j])
			      j = j + 1
			end
			table.insert(row_return,new_row)
		end


		decrypt.init()
		decrypt.fields(field_return)
		decrypt.rows(row_return)
		--decrypt.print()
		row_return2 = {decrypt.get_rows()}

		local current_type = inj.type
		proxy.response.type = proxy.MYSQLD_PACKET_OK

		proxy.response.resultset = {
				fields = field_return ,
				rows =  row_return2  }

		--proxy.response.resultset = res
		return proxy.PROXY_SEND_RESULT	
	end
end
