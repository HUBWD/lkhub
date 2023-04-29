# Lkhub Bypass

This is an example of how to perform a bypass on a low-quality and insecure hub using httpspy and Hookfunction. The goal is to allow the code to execute without the need for a key system check.

## Author

This bypass code was developed by Jeff for [lkhub](https://lkhub.net/), a Roblox game hub created by LeoKholYt. You can contact them through the lkhub Discord: https://discord.com/invite/Zj2A39EeCt.

LeoKholYt's Github profile is: https://github.com/LeoKholYt/.

### Video Tutorial

Here is a [video tutorial](https://www.youtube.com/live/C15RYsFWiYE?feature=share) that shows how to create a bypass for lkhub. The video was created by Jeff.

### Discord Server

Join our community on Discord: https://discord.com/invite/DZEFJQRmV7

### Bypass

Bypass code developed by Jeff:

```lua
local linkGithub="https://raw.githubusercontent.com/HUBWD/lkhub/main/"
local _version=game:HttpGet(linkGithub .. "version.txt")
loadstring(game:HttpGet(linkGithub .. "Backup/" .. _version .. "/loaded.lua"))()
```

### Original Code to Run Lkhub

```lua
loadstring(game:HttpGet("https://lkhub.net/s/loader.lua"))();
```

## Difficulty

- [x] Low
- [ ] Medium
- [ ] High

The key system uses only a simple string comparison. The key system compares the string "Whitelisted" with itself using the syntax `if "Whitelisted" == "Whitelisted" then`.

## Methods Used for Bypass

- [x] Using httpspy to obtain links
- [x] Using Hookfunction to manipulate the Whitelisted verification result

## Steps to Create the Bypass

1. I ran HttpSpy with the following code:

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/HttpSpy/main/init.lua"))({
    AutoDecode = true, -- Automatically decodes JSON
    Highlighting = true, -- Highlights the output
    SaveLogs = true, -- Save logs to a text file
    CLICommands = true, -- Allows you to input commands into the console
    ShowResponse = true, -- Shows the request response
    API = true, -- Enables the script API
    BlockedURLs = {} -- Blocked urls
});
```

2. Next, I ran lkhub with the following code:

```lua
loadstring(game:HttpGet("https://lkhub.net/s/loader.lua"))();
```

3. After running lkhub, I obtained a key and by monitoring requests with HttpSpy, I identified that the following URL was used to check if the key was valid:

`https://lkhub.net/api/check.php?key=lk_aJQEemnWPvAOiBkbTWHB9iCV`

4. I noticed that the URL returned only a string "Whitelisted" if the key was valid.

5. I used Lua's `hookfunction` function to intercept HTTP requests made by the game and manipulate the response of the `https://lkhub.net/api/check.php` request. The code I used was:

```lua
local old;old=hookfunction(game.HttpGet,function(...)
    local args={...}
    if (args[2] :: string):find("http://lkhub.net/api/check.php")then
        return "Whitelisted"
    end;
    return old(...)
end)
```