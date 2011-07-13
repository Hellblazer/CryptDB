function read_query( packet )
	if string.byte(packet) == proxy.COM_QUERY then
	   	query = string.sub(packet,2):gsub("[\n\r\t]"," ");
		print(query..";")
	end
end

