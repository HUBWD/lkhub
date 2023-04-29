if bypasslkhub_system_key then
	local lkhubLink = "https://lkhub.net/"
	local lkhubBackupLink = "https://raw.githubusercontent.com/HUBWD/lkhub/main/Backup/v0.0.2/script/"
	local leoKholYtLink = "https://raw.githubusercontent.com/LeoKholYt/"
	local list_json = game:GetService("HttpService"):JSONDecode(game:HttpGet(lkhubBackupLink .. "data/list.json"))

	local httpGetLinks = {
		[lkhubLink .. "api/check.php"] = "Whitelisted", --Bypass Key
		[lkhubLink .. "s/loader.lua"] = lkhubBackupLink .. "lib/loader.lua",
		
		--data
		[leoKholYtLink .. "lkhub/main/list.json"] = lkhubBackupLink .. "data/list.json",
		[leoKholYtLink .. "lkhub/main/lol.json"] = lkhubBackupLink .. "data/lol.lua",
		
		--lib
		[leoKholYtLink .. "roblox/main/discord_lib_mod.lua"] = lkhubBackupLink .. "lib/discord_lib_mod.lua",
		[lkhubLink .. "s/ESP.lua"] = lkhubBackupLink .. "lib/ESP.lua",
		[leoKholYtLink .. "lkhub/main/esp.lua"] = lkhubBackupLink .. "lib/esp_1.lua",
		[leoKholYtLink .. "roblox/main/esp.lua"] = lkhubBackupLink .. "lib/esp_2.lua",
		[leoKholYtLink .. "uilibs/main/finity.lua"] = lkhubBackupLink .. "lib/finity.lua",
		[lkhubLink .. "s/lib.lua"] = lkhubBackupLink .. "lib/lib.lua",
		[leoKholYtLink .. "roblox/main/lk_serverhop.lua"] = lkhubBackupLink .. "lib/lk_serverhop.lua",
		[lkhubLink .. "s/LKHUB_Module.lua"] = lkhubBackupLink .. "lib/LKHUB_Module.lua",
		
		--services
		[lkhubLink .. "s/universal.lua"] = lkhubBackupLink .. "services/universal.lua"
	}

	for i, data in pairs(list_json) do
		if data["s"] and string.match(data["s"], "%.lua$") then
			httpGetLinks[lkhubLink .. "s/" .. data["s"]] = lkhubBackupLink .. data["s"]
		end
	end


	local oldHttpGet;oldHttpGet = hookfunction(game.HttpGet, function(method, url, ...)
		local urlFilter=url:gsub("%?key=.+", ""):gsub("^http://", "https://")
		local override = httpGetLinks[urlFilter]
		if override then
			if string.match(override, "^https?://")then
				return oldHttpGet(method,override,...)
			end
			return override
		end
		return oldHttpGet(method, url, ...)
	end)
	getgenv().bypasslkhub_system_key=true;
end
loadstring(
	game:HttpGet(
		"https://raw.githubusercontent.com/HUBWD/lkhub/main/Backup/v0.0.2/script/loader.lua"
	)
)([[
--Just like a delicious coffee, a good exploit script should be strong and resilient. Unfortunately, lkhub is neither of those things. It's like drinking dirty water - no flavor, no benefits, and no safety.

--LKHub key system:
if "lkhub"=="lkhub" then
	print("LKHub is like a castle without walls - easy to enter and with no protection whatsoever.");
	return;
end]]);