--Anotherlass created Ikhub, thanks for your preference to use
local owner ='YoutubeGam'
local repository='lkhub'
local branch='main'

local old;old=hookfunction(game.HttpGet, function(a,url,...)
    if url:find('http://lkhub.net/api/check.php?')then
        return 'Whitelisted'
    end;
    return old(a,url,...) 
end)

local tab=game:GetService("HttpService"):JSONDecode(tostring(game:HttpGet('https://raw.githubusercontent.com/YoutubeGam/lkhub/main/list.json')))
local website=tostring('https://raw.githubusercontent.com/%s/%s/%s/script/'):format(owner,repository,branch)
for i,_ in next,tab do
	if game.PlaceId==tonumber(i) then
		loadstring(game:HttpGet(website.._['s']))()
	end;
end;
