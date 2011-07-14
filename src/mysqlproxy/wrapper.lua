assert(package.loadlib(os.getenv("EDBDIR").."/libexecute.so", "luaopen_resultset"))()

current_query = {}

-- A table is sensitive if it has an ENCFOR, GIVESPSSWD, HASACCESSTO annotation
-- All inserts, updates, deletes to sensitive tables go to C
-- All selects from sensitive tables which contain * before FROM or contain sensitive fields go to C
-- All inserts and deletes to activeusers go to C

-- sensitive_fields is a table of tables, such that sensitive_fields[tablename] = {the sensitive fields in tablename}
sensitive_fields = {}

-- auto_inc is a table which maps the tables that have auto_incs to their last increment
auto_inc = {}

use_enc_annotation = true
VERBOSE = true

-- removes all whitespace from the beginning and end of input str
function strip(str)
	return str:gsub("[ \t\r\n]*(.)[ \t\r\n]*","%1")
end

-- prints input str if VERBOSE flag is set to true
function myprint(str)
	 if (VERBOSE) then
	    print(str)
	 end
end

function connect_server()
	myprint("NEW CONNECTION"..os.time().."===========================================================")
	CryptDB.init("localhost","root","letmein","mysql")
	s_map_names = {CryptDB.get_map_names()}
	auto_names = {CryptDB.get_auto_names()}
	myprint("names okay")
	s_fields = {CryptDB.get_map_fields()}
	auto_numbers = {CryptDB.get_auto_numbers()}
	myprint("fields/numbers okay")
	for i,j in pairs(s_map_names) do
	    sensitive_fields[j] = s_fields[i]
	end
	for i,j in pairs(auto_names) do
	    auto_inc[j] = auto_numbers[i]
	end
	if (VERBOSE) then
	    for i,j in pairs(sensitive_fields) do
	    	myprint(i..": ")
		for k,l in pairs(j) do
		    myprint(k,l)
		end
	    end
	    for i,j in pairs(auto_inc) do
	    	myprint(">_<")
	    	myprint(i.."@"..j)
	    end
	end
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

function get_table_name(query)
	local table_name = ""
	if (query:match("^%s*[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee]")) then
	   query:gsub("^%s*[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] ([^(]+)", function(w) table_name = w:gsub("[ ]","") end)
	end
	if (query:match("^%s*[Ss][Ee][Ll][Ee][Cc][Tt]")) then
	   query:gsub("^%s*[Ss][Ee][Ll][Ee][Cc][Tt] [^ ]+ [Ff][Rr][Oo][Mm] ([^ ]+)", function(w) table_name = w:gsub("[ ]","") end)
	end
	if (query:match("^%s*[Ii][Nn][Ss][Ee][Rr][Tt] [Ii][Nn][Tt][Oo]")) then
	   query:gsub("^%s*[Ii][Nn][Ss][Ee][Rr][Tt] [Ii][Nn][Tt][Oo] ([^ ]+)", function(w) table_name = w:gsub("[ ]","") end)
	end
	if (query:match("^%s*[Uu][Pp][Dd][Aa][Tt][Ee]")) then
	   query:gsub("^%s*[Uu][Pp][Dd][Aa][Tt][Ee] ([^ ]+)", function(w) table_name = w:gsub("[ ]","") end)	
	end
	return table_name
end

function sensitive_enc(create)
        if not create:upper():match("ENC") then
           return
        end
        local fields = {}
	local table_name = get_table_name(create)
        create = create:gsub("[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] [^(]+ [(]", "")
        create = create:sub(1,create:len()-1)
        for sub in string.gmatch(create, "[^,]+[,]?") do
            if sub:upper():match("ENC") then
               match = false
               local name = sub:gsub("[ /t/r/n]?(.-) .+","%1")
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
        if (table.getn(fields) ~= 0) then
            sensitive_fields[table_name] = fields
            CryptDB.add_to_map(table_name,fields)
        end
        --for k,v in pairs(fields) do print(k,v) end
end

function sensitive(create)
	myprint("~~finding sensitive~~")
        local table_name = get_table_name(create)
        local fields = {}
	myprint("tablename is "..table_name)
        create = create:gsub("^%s*[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] [^(]+ [(]", "")
        create = create:sub(1,create:len()-1)
        for sub in string.gmatch(create, "[^,]+[,]?") do
            myprint("substring is "..sub)
            if sub:upper():match(".+ GIVESPSSWD") then
	           match = false
               local name = sub:gsub("[ /t/r/n]?(.-) .+","%1")
               name = strip(name)
               for i,j in pairs(fields) do
                   if (j:match(name)) then
                      match = true
                   end
               end
               if not match then
                  table.insert(fields, name)
               end
            end
            if sub:upper():match("ENCFOR") or sub:upper():match("HASACCESSTO") then
               match = false
               myprint("hasaccessto matching bit: "..sub)
               local name1;
               local name2;
               if sub:upper():match("ENCFOR") then
                   name1 = sub:gsub("[ \t\r\n]*(.-) [Ee][Nn][Cc][Ff][Oo][Rr] .+","%1")
                   name2 = sub:gsub(".+ [Ee][Nn][Cc][Ff][Oo][Rr] (.-) .+","%1")
               end
               if sub:upper():match("HASACCESSTO") then
                   name1 = sub:gsub("[ \t\r\n]*(.-) .*[ /t/n/r]?[Hh][Aa][Ss][Aa][Cc][Cc][Ee][Ss][Ss][Tt][Oo] .+","%1")
                   name2 = sub:gsub(".+ [Hh][Aa][Ss][Aa][Cc][Cc][Ee][Ss][Ss][Tt][Oo] (.-) .+","%1")
               end
	       myprint("names gotten: ")
               myprint(name1,name2)
               for i,j in pairs(fields) do
                   if (j:match(name1)) then
                      match = true
                   end
               end
               if not match then
                  table.insert(fields, name1)
               end
               match = false
               for i,j in pairs(fields) do
                   if (j:match(name2)) then
                      match = true
                   end
               end
               if not match then
                  table.insert(fields, name2)
               end
            end
        end
        if (table.getn(fields) ~= 0) then
           sensitive_fields[table_name] = fields
           CryptDB.add_to_map(table_name,fields)
           myprint("SENSITIVITY")
        end
        if (VERBOSE) then
                for k,v in pairs(fields) do print(table_name..":",k,v) end
        end
end

function auto(create)
	myprint("finding autoinc in "..create)
	local table_name = get_table_name(create)
	if (create:match("[Aa][Uu][Tt][Oo]_[Ii][Nn][Cc][Rr][Ee][Mm][Ee][Nn][Tt]")) then
	   auto_inc[table_name] = 0
	   CryptDB.edit_auto(table_name,0)
	   myprint(table_name)
	end
end

function cpattern_find(query)
	myprint("finding cpattern?")
        --query = query:upper()
        local first_word = query:gsub("^%s*(.-) .+","%1")
        myprint(first_word)
        if (first_word:upper():match('SELECT')) then
           myprint("select")
           local post_from = query:gsub("(.* [Ff][Rr][Oo][Mm]) (.*)", "%2")
           table_sense = false
           for i,j in pairs(sensitive_fields) do
               if post_from:match(i) or i:match(post_from) then
                  myprint("matched "..i)
                  table_sense = true
               end
           end
           if not table_sense then
              myprint("not to C")
              return false
           end
           local pre_from = query:gsub("(.*) ([Ff][Rr][Oo][Mm] .*)", "%1")
           -- and there's * before FROM, return true
           if string.match(pre_from,'*') then
                 return true
           end
           -- and there's anything sensitive in the whole query, return true
           myprint("matching...")
           for i,j in pairs(sensitive_fields) do
                  --print(i,j)
                  for k,l in pairs(j) do
                      --print(k,l)
                      if string.match(query,l) then
                         myprint("matched "..l)
                         return true
                      end
                  end
           end
           myprint("not to C")
           return false
        end
        if first_word:upper():match('UPDATE') then
           myprint("update")
           local table_name = query:gsub('[Uu][Pp][Dd][Aa][Tt][Ee] (.-) (.+)','%1')
           table_name = strip(table_name:gsub("^%s*(.+)[ \n\r\t](.*)","%1"))
           myprint(table_name)
           for i,j in pairs(sensitive_fields) do
               myprint(i)
               if table_name:match(i) or i:match(table_name) then
                  myprint("matched "..i)
                  return true
               end
           end
        end
        if first_word:upper():match('DELETE') then
           myprint("delete")
           local table_name = query:gsub('[Dd][Ee][Ll][Ee][Tt][Ee][ \n\t\r]+[Ff][Rr][Oo][Mm] (.-) (.+)','%1')
           table_name = strip(table_name:gsub("^%s*(.+)[ \n\r\t](.*)","%1"))
           if (table_name:lower():match('activeusers')) then
               return true
           end
           for i,j in pairs(sensitive_fields) do
               if table_name:match(i) or i:match(table_name) then
                  myprint("matched "..i)
                  return true
               end
           end
        end
        if first_word:upper():match('INSERT') then
           myprint("insert")
           local table_name = query:gsub('[Ii][Nn][Ss][Ee][Rr][Tt][ \n\t\r]+[Ii][Nn][Tt][Oo] (.-) (.+)','%1')
           table_name = strip(table_name:gsub("^%s*(.+)[ \n\r\t](.*)","%1"))
           if (table_name:lower():match('activeusers')) then
               return true
           end
           for i,j in pairs(sensitive_fields) do
               if table_name:match(i) or i:match(table_name) then
                  myprint("matched "..i)
                  return true
               end
           end
        end
        myprint("not to C")
        return false
end

function pass_to_c(query)
	myprint("pass to c")
	-- if this table has an auto_inc, find the last insert ID
	local table_name = get_table_name(query)
	local insert_id = 0
	if (auto_inc[table_name] ~= nil) then
	   insert_id = auto_inc[table_name]
	end
	new_queries = CryptDB.pass_query(query, insert_id)
	myprint("we got the following queries from c++:")
	if (VERBOSE) then
	   for i,j in pairs(new_queries) do print("  ",i,j) end
	end
	current_query[new_queries[#new_queries]] = query
	return new_queries
end

function read_query(packet)
	local status, err = pcall(read_query_real, packet)
	if status then
		return err
	else
		print("read_query: " .. err)
		return proxy.PROXY_SEND_QUERY
	end
end

function read_query_real(packet)
	if string.byte(packet) == proxy.COM_QUERY then
		myprint("-------------------------------New Query--------------------------")
		myprint("read_query got query: " .. string.sub(packet, 2))
		local query = string.sub(packet, 2)
		local replacing = false

		local tk = require('proxy.tokenizer')
		local tokens = tk.tokenize(query)

		if tokens[1].token_name == 'TK_SQL_CREATE' then
		   if use_enc_annotation then
		      sensitive_enc(query)
		   else
		      sensitive(query)
		   end
		   auto(query)
		   new_queries = pass_to_c(query)
		   last_query = new_queries[table.getn(new_queries)]
		   table.remove(new_queries,table.getn(new_queries))
		   for i,v in pairs(new_queries) do
		       proxy.queries:append(2, string.char(proxy.COM_QUERY) .. v, { resultset_is_needed = true } )
		   end
		   proxy.queries:append(3, string.char(proxy.COM_QUERY) .. last_query, { resultset_is_needed = true } )
       		   replacing = true
		elseif cpattern_find(query) then
		   myprint("to c")
		   new_queries = pass_to_c(query)
		   last_query = new_queries[table.getn(new_queries)]
		   table.remove(new_queries)
		   for i,v in pairs(new_queries) do
		       proxy.queries:append(2, string.char(proxy.COM_QUERY) .. v, { resultset_is_needed = true } )
		   end
		   if query:upper():match('^%s*SELECT') then
		      proxy.queries:append(3, string.char(proxy.COM_QUERY) .. last_query, { resultset_is_needed = true } )
		      current_query[last_query] = query
		   else
		      if query:upper():match('^%s*INSERT INTO') then
		      	 proxy.queries:append(4, string.char(proxy.COM_QUERY) .. last_query, { resultset_is_needed = true } )
		      	 current_query[last_query] = query
		      else
			 proxy.queries:append(5, string.char(proxy.COM_QUERY) .. last_query, { resultset_is_needed = true} )
		      end
		   end
       		   replacing = true
		end
		if replacing then
		   return proxy.PROXY_SEND_QUERY
		end
	end
end

function read_query_result(inj)
	local status, err = pcall(read_query_result_real, inj)
	if status then
		return err
	else
		print("read_query_result: " .. err)
		return proxy.PROXY_SEND_RESULT
	end
end

function read_query_result_real(inj)
	local res = assert(inj.resultset)
	query = inj.query:sub(2,inj.query:len())
	if(res) and (inj.id == 4) then
		local table_name = get_table_name(query)
		if (auto_inc[table_name] ~= nil) then
		   --TODO send query SELECT LAST_INSERT_ID();
		   --maybe okay like this?
		   auto_inc[table_name] = auto_inc[table_name] + 1
		   CryptDB.edit_auto(table_name,auto_inc[table_name]+1)
		   myprint("autoinc "..table_name)
		end
	end
	if(res) and (inj.id == 3) then
		original_query = current_query[query]
		myprint(query)
		myprint(original_query)
		myprint("  injected result-set: id = " .. inj.id .. " from " .. original_query)
	else
		myprint("  injected result-set: id = " .. inj.id .. " from " .. query)
	end

	-- id is 3 when query was SELECT... we expect a response
	if (inj.id ~= 3) and (inj.id ~= 4) then
	   myprint(">_<")
	   return proxy.PROXY_IGNORE_RESULT
	end
	if (res) and (inj.id == 3) then
		local field_return = {}
		local i = 1
		local isblob = {}
		while res.fields[i] do
		      table.insert(field_return, { type=res.fields[i].type, name=res.fields[i].name})
		      if (res.fields[i].type == proxy.MYSQL_TYPE_BLOB ) then
		      	 --myprint("blob")
		      	 table.insert(isblob,"true")
		      else
		      	 --myprint("not blob")
			 table.insert(isblob,"false")
		      end 
		      i = i + 1
		end
		--for i,j in pairs(inj.fields) do print(i,j) end
		--for i,j in pairs(inj.field_return) do print(i,j) end

	   	local row_return = {}
		if (not res.rows) then return end
		for row in res.rows do
			--print("    injected query returned: " .. row[1]-1)
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

		myprint("  resultset to c...")
		CryptDB.new_res(original_query)
		myprint("  initialized new resultset")
		CryptDB.fields(field_return)
		myprint("  sent field_return")
		--for i,j in pairs(row_return) do for k,l in pairs(j) do print(k,l) end end
		CryptDB.rows(row_return)
		myprint("  send row_return")
		CryptDB.decrypt()
		myprint("decrypted")
		local field_names = CryptDB.get_fields()
		myprint("  got new fields:")
		local row_return2 = {CryptDB.get_rows()}
		myprint("  got new rows:")
		for i,j in pairs(row_return2) do for k,l in pairs(j) do print(i,j,k,l) end end


		local current_type = inj.type
		proxy.response.type = proxy.MYSQLD_PACKET_OK

		local field_return2 = {}
		for i,j in pairs(field_names) do
		    for a,b in pairs(field_return) do
			if (j == b.name) then
			   table.insert(field_return2, {type=b.type, name=j})
			end
		    end
		end

		proxy.response.resultset = {
				fields = field_return2 ,
				rows =  row_return2  }

		return proxy.PROXY_SEND_RESULT	
	end
end
