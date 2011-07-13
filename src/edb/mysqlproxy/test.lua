assert(package.loadlib("/u/raluca/EncryptDB/src/EDB/libexecute.so","luaopen_resultset"))()
--assert(package.loadlib("/home/kis/EncryptDB/src/EDB/libexecute.so","luaopen_resultset"))()

current_query = ""

sensitive_fields = {}

function connect_server()
	CryptDB.init("localhost","root","letmein","phpbb")
end

function unmarshallBinary(b)
	local k = 3
	local bin = ""
	while k < b:len() do
	      bin = bin..string.char(tonumber("0x"..b:sub(k,k+1)))
	      k = k + 2
	end
	return bin
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

function only_printable(string)
	local chars = {string:byte()}
	printable = true
	for i,j in ipairs(chars) do
	    if (j <= 31) or (j >= 127) then
	       printable = false
	       break
	    end
	end
	return printable
end

function sensitive_enc(create)
	if not create:upper():match("ENC") then
	   return
	end
	local table_name = ""
	local fields = {}
	string.gsub(create:upper(), "CREATE TABLE ([^(]+)", function(w) table_name = w end)
	create = string.gsub(create:upper(), "CREATE TABLE [^(]+ [(]", "")
	create = create:sub(1,create:len()-1)
	for sub in string.gmatch(create:upper(), "[^,]+[,]?") do
	    if sub:upper():match("ENC") then
	       match = false
	       local name = sub:gsub("[ ]?(.-) .+","%1")
	       for i,j in pairs(fields) do
	       	   if (j:match(name)) then
		      match = true
		   end
	       end
	       if not match then
	       	  table.insert(fields, name)
	       end
	    end
	end
	sensitive_fields[table_name] = fields
	for k,v in pairs(fields) do print(k,v) end
end

function pass_to_c(query)
	local full_results = {CryptDB.execute(query)}
	print(table.getn(full_results))
	if table.getn(full_results) == 0 then
	   return {},{}
	end
	--how are we getting field types here?
	local fields = {}
	for i,j in ipairs(full_results[1]) do
	    table.insert(fields,i,{name=j,type=proxy.MYSQL_PROXY_INT24})
	end
	local rows = {}
	for i=1,table.getn(full_results) do
	    if i ~= 1 then
	       table.insert(rows,i-1,full_results[i])
	    end
	end
	return fields, rows
end	

function cpattern_find(query)
        query = query:upper()
        if string.match(query:upper(), 'SELECT') and not string.match(string.upper(query), 'DATABASE') or string.match(query:upper(), 'UPDATE') or string.match(query:upper(), 'DELETE') or string.match(query:upper(), 'INSERT') then
           -- if everything after from is not sensitive, return FALSE
           local post_from = query:gsub("(.* FROM) (.*)", "%2")
           table_sense = false
           for i,j in pairs(sensitive_fields) do
               if post_from:match(i) or i:match(post_from) then
                  -- print("matched "..i)
                  table_sense = true
               end
           end
           if not table_sense then
              return false
           end
           if post_from:match('*') then
              table_sense = true
           end

           -- if there is sensitivity after FROM
           -- and it's SELECT or DELETE
           local pre_from = query:gsub("(.*) (FROM .*)", "%1")
           if string.match(query,'SELECT') or string.match(query,'DELETE') then
              -- and there's * before FROM, return true
              if string.match(pre_from,'*') then
                 return true
              end
              -- and there's anything sensitive in the whole query, return true
              for i,j in pairs(sensitive_fields) do
                  for k,l in pairs(j) do
                      if string.match(query,l) then
                         return true
                      end
                  end
              end
              -- otherwise, return false
              return false
           end

           -- and it's a INSERT or DELETE, return  true
           if string.match(query,'INSERT') or string.match(query,'DELETE') then
              return true;
           end
        end
        return false
end





function read_query( packet )
	if string.byte(packet) == proxy.COM_QUERY then
		print("we got a normal query: " .. string.sub(packet, 2))
		local query = string.sub(packet, 2)
		return proxy.PROXY_SEND_QUERY
	end
end	   

function read_query_result(inj)
	proxy.response.type = proxy.MYSQLD_PACKET_OK
	local row_return = {}
	if inj.resultset.rows then
	   print("********************************************************")
                for row in inj.resultset.rows do
                        local j = 1
                        local new_row = {}
                        while row[j] ~= nil do
                              table.insert(new_row, row[j])
                              j = j + 1
                        end
                        table.insert(row_return,new_row)
                end
	field_return = {}
	local i = 1
	while inj.resultset.fields[i] do
	      table.insert(field_return, {type=proxy.MYSQL_TYPE_INT24,name=res.fields[i].name})
	end
	proxy.response.resultset = {fields=field_return,rows=row_return}
	return proxy.PROXY_SEND_RESULT
	end
end
