--Anotherlass created Ikhub, thanks for your preference to use
local owner ='YoutubeGam'
local repository='lkhub'
local branch='main'

local website=tostring('https://raw.githubusercontent.com/%s/%s/%s/'):format(owner,repository,branch)..'%s'
assert(hookfunction,'Your exploit is not compatible')

local function URL_replacement(...)
    local args={...};
    for i,_ in next,args do
        local url_1=_[1];
        local url_2=_[2];
        local bool=_[3];
        local old;old=hookfunction(game.HttpGet, function(a,url,...)
            if url:find(url_1) and bool then
                return url_2
			elseif url:find(url_1) and not(bool) then
                return old(a,url_2,...) 
            end;
            return old(a,url,...) 
        end)
    end;
end;
URL_replacement(
    {'http://lkhub.net/api/check.php?','Whitelisted',true},
    {'https://raw.githubusercontent.com/LeoKholYt/uilibs/main/finity.lua',website:format('UI.lua')},
    {'https://raw.githubusercontent.com/LeoKholYt/lkhub/main/list.json',website:format('list.json')}
);

local old;old=hookfunction(game.HttpGet, function(a,url,...)
    local min,max=url:find('https://lkhub.net/s/')
    if url:find('https://lkhub.net/s/loader.lua')then
        return old(a,website:format(url:sub(max+1,url:len())),...)
    elseif url:find('https://lkhub.net/s/')then
        return old(a,website:format('script/'..url:sub(max+1,url:len())),...)
    end;
    return old(a,url,...) 
end)

add_menu=game:GetService("CoreGui").ChildAdded:Connect(function(obj)
	if rawequal(obj.Name,'LKHUB')then
		local frame=obj:WaitForChild'Frame'
		local bad_exploit=obj:WaitForChild'bad_exploit'
		frame.title.Text='Anotherlass'
		bad_exploit.title.Text='Anotherlass'
		frame['1'].Text='Please type anything to access our HUB, we work hard, visit our discord site: https://discord.gg/u2N2KKc6p7'
		add_menu:Disconnect()
	end;
end);
