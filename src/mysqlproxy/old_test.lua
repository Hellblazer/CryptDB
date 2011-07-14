package.loadlib("/home/kis/EncryptDB/mysqlproxy/libincr.so","luaopen_incr")()

function read_query( packet )
	if string.byte(packet) == proxy.COM_QUERY then
		print("we got a normal query: " .. string.sub(packet, 2))

		proxy.queries:append(1, packet )
		proxy.queries:append(2, string.char(proxy.COM_QUERY) .. "SELECT NOW()", { resultset_is_needed = true } )
		a = incr.incr(1)
		return proxy.PROXY_SEND_QUERY
	end
end

function read_query_result(inj)
	print("injected result-set: id = " .. inj.id)
	if (inj.id == 2) then
		for row in inj.resultset.rows do
			print("injected query returned: " .. row[1])
		end

		return proxy.PROXY_IGNORE_RESULT
	end
end