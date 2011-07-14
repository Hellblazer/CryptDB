assert(package.loadlib("/u/raluca/EncryptDB/src/EDB/libexecute.so","luaopen_resultset"))()
--assert(package.loadlib("/home/kis/EncryptDB/src/EDB/libexecute.so","luaopen_resultset"))()

current_query = ""


-- A table is sensitive if it has an encfor, givespsswd, or hasaccessto annotation
-- All inserts, updates, deletes to sensitive tables go to C
-- All selects from sensitive tables which contain * before from or sensitive fields anywhere got to C
-- All inserts and deletes to activeusers go to C
sensitive_fields = {}

-- set this to true to use ENC as the annotation scheme
-- set this to false to use ENCFOR, ACCESSTO, GIVESPSSWD, etc.
use_enc_annotation = false
VERBOSE = true

function strip(str)
	return str:gsub("[ \t\r\n]*(.-)[ \t\r\n]*","%1")
end

function myprint(str)
	if (VERBOSE) then
		print(str)
	end
end

function connect_server()
	myprint("NEW CONNECTION"..os.time())
	CryptDB.init("localhost","root","letmein","phpbb")
	s_names = {CryptDB.get_map_names()}
	myprint("map names okay")
	s_fields = {CryptDB.get_map_fields()}
	myprint("map fields okay")
	for i,j in pairs(s_names) do
	    sensitive_fields[j] = s_fields[i]
	end
	if (VERBOSE) then
		for i,j in pairs(sensitive_fields) do print(i..": ") for k,l in pairs(j) do myprint(k,l) end end
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

function sensitive_enc(create)
	if not create:upper():match("ENC") then
	   return
	end
	local table_name = ""
	local fields = {}
	create:gsub("[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] ([^(]+)", function(w) table_name = w end)
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
	local table_name = ""
	local fields = {}
	create:gsub("^%s*[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] ([^(]+)", function(w) table_name = w:gsub("[ ]","") end)
	create = create:gsub("^%s*[Cc][Rr][Ee][Aa][Tt][Ee] [Tt][Aa][Bb][Ll][Ee] [^(]+ [(]", "")
	create = create:sub(1,create:len()-1)
	for sub in string.gmatch(create, "[^,]+[,]?") do
	    --print(sub)
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
	       --print(sub)
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
	       --print(name1,name2)
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



function cpattern_find(query)
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
	local full_results = {CryptDB.execute(query)}
	--print("length in lua is " .. table.getn(full_results))
	if table.getn(full_results) == 0 then
	   return {},{}
	end
	local fields = {}
	for i,j in ipairs(full_results[1]) do
	    table.insert(fields,i,{name=j,type=proxy.MYSQL_PROXY_INT24})
	end
	myprint("fields from C okay")
	local rows = {}
	for i=1,table.getn(full_results) do
	    if i ~= 1 then
	       table.insert(rows,i-1,full_results[i])
	    end
	end
	myprint("rows from C okay")
	return fields, rows
end	



function read_query( packet )
	myprint("read_query query is " .. string.sub(packet, 2))
	if string.byte(packet) == proxy.COM_QUERY then
	   	myprint("------------------------------------New Query-------------------------")
		myprint("read_query query is " .. string.sub(packet, 2))
		local query = string.sub(packet, 2)
		if string.match(string.upper(query), 'CREATE TABLE') then
		   if use_enc_annotation then
		      sensitive_enc(query)
		   else
		      sensitive(query)
		   end
		   pass_to_c(query)
		   proxy.response.type = proxy.MYSQLD_PACKET_OK
		   proxy.response.resultset = nil
		   return proxy.PROXY_SEND_RESULT
		end
		if cpattern_find(query) then
		   myprint("to c")
		   local_fields, local_rows = pass_to_c(query)

		   if query:upper():match('^%s*SELECT') then
		      proxy.response.type = proxy.MYSQLD_PACKET_OK
		      proxy.response.resultset = {fields=local_fields, rows=local_rows}
		      return proxy.PROXY_SEND_RESULT
		   end
		   -- if insert, spoof an autoincrement value
		   if table.getn(local_fields) ~= 0 and query:upper():match('^%s*INSERT') then
		      myprint("got a field name:")
		      myprint(local_fields[1]['name'])
		      myprint(local_fields[1]['name']:lower():match('cryptdb_autoinc'))
		   end
		   if query:upper():match('^%s*INSERT') and table.getn(local_fields) ~= 0 and local_fields[1]['name']:lower():match('cryptdb_autoinc') then
		      myprint("!!!")
		      proxy.response.type = proxy.MYSQLD_PACKET_OK
		      proxy.response.affected_rows = 1
		      myprint(local_rows[1][1])
		      proxy.response.insert_id = local_rows[1][1]
		      return proxy.PROXY_SEND_RESULT
		   else
		      proxy.response.type = proxy.MYSQLD_PACKET_OK
		      proxy.response.resultset = nil
		      return proxy.PROXY_SEND_RESULT
		   end
		end
	end
end	   

function read_query_result(inj)
	local res = assert(inj.resultset)
	-- spoofs insert_id for autoincrement
	proxy.response.type = proxy.MYSQLD_PACKET_OK		      
	proxy.response.affected_rows = 10
	proxy.response.insert_id = 1
	return proxy.PROXY_SEND_RESULT
end
