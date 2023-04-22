local old;old=hookfunction(game.HttpGet,function(...)
	local args={...}
	if (args[2] :: string):find("http://lkhub.net/api/check.php")then
		return "Whitelisted"
	end;
	return old(...)
end)

loadstring(game:HttpGet("https://lkhub.net/s/loader.lua"))();