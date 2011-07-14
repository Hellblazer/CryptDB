 function read_query( packet )
   if string.byte(packet) == proxy.COM_QUERY then
     local query = string.sub(packet, 2)
     print ("received " .. query)
     local replacing = false
     -- matches "CRATE" as first word of the query
     if string.match(string.upper(query), '^%s*CRATE') then
         query = string.gsub(query,'^%s*%w+', 'CREATE')
         replacing = true
     -- matches "SLECT" as first word of the query
     elseif string.match(string.upper(query), '^%s*SLECT') then
         query = string.gsub(query,'^%s*%w+', 'SELECT')
         replacing = true
     end
     if (replacing) then
         print("replaced with " .. query )
         proxy.queries:append(1, string.char(proxy.COM_QUERY) .. query )
         return proxy.PROXY_SEND_QUERY
     end
   end
 end
