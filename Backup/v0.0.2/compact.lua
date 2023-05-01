assert(isfolder("lkhub"),"Error: lkhub folder not found. The code cannot proceed.")

local Serializer = {};do--local Serializer = loadstring(game:HttpGet("https://raw.githubusercontent.com/NotDSF/leopard/main/rbx/leopard-syn.lua"))();
    local config   = { spaces = 4, highlighting = false };
    local clonef   = clonefunction;
    local str      = string;
    local gme      = game;
    local sub      = clonef(str.sub);
    local format   = clonef(str.format);
    local rep      = clonef(str.rep);
    local byte     = clonef(str.byte);
    local match    = clonef(str.match);
    local getfn    = clonef(gme.GetFullName);
    local info     = clonef(debug.getinfo);
    local huge     = math.huge; -- just like your mother
    local Type     = clonef(typeof);
    local Pairs    = clonef(pairs);
    local Assert   = clonef(assert);
    local tostring = clonef(tostring);
    local concat   = clonef(table.concat);
    local getmet   = clonef(getmetatable);
    local rawget   = clonef(rawget);
    local rawset   = clonef(rawset);
    local Tab      = rep(" ", config.spaces or 4);
    local Serialize;
    
    -- Kill me
    local DataTypes = {
      Axes = true,
      BrickColor = true,
      CatalogSearchParams = true,
      CFrame = true,
      Color3 = true,
      ColorSequence = true,
      ColorSequenceKeypoint = true,
      DateTime = true,
      DockWidgetPluginGuiInfo = true,
      Enum = true,
      Faces = true,
      Instance = true,
      NumberRange = true,
      NumberSequence = true,
      NumberSequenceKeypoint = true,
      OverlapParams = true,
      PathWaypoint = true,
      PhysicalProperties = true,
      Random = true,
      Ray = true,
      RaycastParams = true,
      RaycastResult = true,
      Rect = true,
      Region3 = true,
      Region3int16 = true,
      TweenInfo = true,
      UDim = true,
      UDim2 = true,
      Vector2 = true,
      Vector2int16 = true,
      Vector3 = true,
      Vector3int16 = true
    }
    
    local function Tostring(obj) 
      local mt, r, b = getmet(obj);
      if not mt or Type(mt) ~= "table" then
        return tostring(obj);
      end;
      
      b = rawget(mt, "__tostring");
      rawset(mt, "__tostring", nil);
      r = tostring(obj);
      rawset(mt, "__tostring", b);
      return r;
    end;
    
    local function serializeArgs(...) 
      local Serialized = {}; -- For performance reasons
    
      for i,v in Pairs({...}) do
        local valueType = Type(v);
        local SerializeIndex = #Serialized + 1;
        if valueType == "string" then
          Serialized[SerializeIndex] = format("\27[32m\"%s\"\27[0m", v);
        elseif valueType == "table" then
          Serialized[SerializeIndex] = Serialize(v, 0);
        else
          Serialized[SerializeIndex] = Tostring(v);
        end;
      end;
    
      return concat(Serialized, ", ");
    end;
    
    local function formatFunction(func)
      if info then -- Creates function prototypes
        local proto = info(func);
        local params = {};
    
        if proto.nparams then
          for i=1, proto.nparams do
            params[i] = format("p%d", i);
          end;
          if proto.isvararg then
            params[#params+1] = "...";
          end;
        end;
    
        return format("function (%s) --[[ Function Name: \"%s\" ]] end", concat(params, ", "), proto.namewhat or proto.name or "");
      end;
      return "function () end"; -- we cannot create a prototype
    end;
    
    local function formatString(str) 
      local Pos = 1;
      local String = {};
      while Pos <= #str do
        local Key = sub(str, Pos, Pos);
        if Key == "\n" then
          String[Pos] = "\\n";
        elseif Key == "\t" then
          String[Pos] = "\\t";
        elseif Key == "\"" then
          String[Pos] = "\\\"";
        else
          local Code = byte(Key);
          if Code < 32 or Code > 126 then
            String[Pos] = format("\\%d", Code);
          else
            String[Pos] = Key;
          end;
        end;
        Pos = Pos + 1;
      end;
      return concat(String);
    end;
    
    -- We can do a little trolling and use this for booleans too
    local function formatNumber(numb) 
      if numb == huge then
        return "math.huge";
      elseif numb == -huge then
        return "-math.huge";
      end;
      return Tostring(numb);
    end;
    
    local function formatIndex(idx, scope)
      local indexType = Type(idx);
      local finishedFormat = idx;
    
      if indexType == "string" then
        if match(idx, "[^_%a%d]+") then
          finishedFormat = format(config.highlighting and "\27[32m\"%s\"\27[0m" or "\"%s\"", formatString(idx));
        else
          return idx;
        end;
      elseif indexType == "table" then
        scope = scope + 1;
        finishedFormat = Serialize(idx, scope);
      elseif indexType == "number" or indexType == "boolean" then
        if config.highlighting then
          finishedFormat = format("\27[33m%s\27[0m", formatNumber(idx));
        else
          finishedFormat = formatNumber(idx);
        end;
      elseif indexType == "function" then
        finishedFormat = formatFunction(idx);
      elseif indexType == "Instance" then
        finishedFormat = getfn(idx);
      else
        finishedFormat = Tostring(idx);
      end;
    
      return format("[%s]", finishedFormat);
    end;
    
    Serialize = function(tbl, scope, checked) 
      checked = checked or {};
    
      if checked[tbl] then
        return format("\"%s -- recursive table\"", Tostring(tbl));
      end;
    
      checked[tbl] = true;
      scope = scope or 0;
    
      local Serialized = {}; -- For performance reasons
      local scopeTab = rep(Tab, scope);
      local scopeTab2 = rep(Tab, scope+1);
    
      local tblLen = 0;
      for i,v in Pairs(tbl) do
        local IndexNeeded = tblLen + 1 ~= i;
        local formattedIndex = format(IndexNeeded and "%s = " or "", formatIndex(i, scope));
        local valueType = Type(v);
        local SerializeIndex = #Serialized + 1;
    
        if valueType == "string" then -- Could of made it inline but its better to manage types this way.
          Serialized[SerializeIndex] = format(config.highlighting and "%s%s\27[32m\"%s\"\27[0m,\n" or "%s%s\"%s\",\n", scopeTab2, formattedIndex, formatString(v));
        elseif valueType == "number" or valueType == "boolean" then
          Serialized[SerializeIndex] = format(config.highlighting and "%s%s\27[33m%s\27[0m,\n" or "%s%s%s,\n", scopeTab2, formattedIndex, formatNumber(v));
        elseif valueType == "table" then
          Serialized[SerializeIndex] = format("%s%s%s,\n", scopeTab2, formattedIndex, Serialize(v, scope+1, checked));
        elseif valueType == "userdata" then
          Serialized[SerializeIndex] = format("%s%s newproxy(),\n", scopeTab2, formattedIndex);
        elseif valueType == "function" then
          Serialized[SerializeIndex] = format("%s%s%s,\n", scopeTab2, formattedIndex, formatFunction(v));
        elseif valueType == "Instance" then
          Serialized[SerializeIndex] = format("%s%s%s,\n", scopeTab2, formattedIndex, getfn(v));
        elseif DataTypes[valueType] then
          Serialized[SerializeIndex] = format("%s%s%s.new(%s),\n", scopeTab2, formattedIndex, valueType, Tostring(v));
        else
          Serialized[SerializeIndex] = format("%s%s\"%s\",\n", scopeTab2, formattedIndex, Tostring(v)); -- Unsupported types.
        end;
    
        tblLen = tblLen + 1; -- # messes up with nil values
      end;
    
      -- Remove last comma
      local lastValue = Serialized[#Serialized];
      if lastValue then
        Serialized[#Serialized] = sub(lastValue, 0, -3) .. "\n";
      end;
    
      if tblLen > 0 then
        if scope < 1 then
          return format("{\n%s}", concat(Serialized));  
        else
          return format("{\n%s%s}", concat(Serialized), scopeTab);
        end;
      else
        return "{}";
      end;
    end;
    
    function Serializer.Serialize(tbl)
      if Type(tbl) ~= "table" then
        error("invalid argument #1 to 'Serialize' (table expected)");
      end;
      Assert(Type(tbl) == "table", "");
      return Serialize(tbl);
    end;
    
    function Serializer.FormatArguments(...) 
      return serializeArgs(...);
    end;
    
    function Serializer.FormatString(str) 
      if Type(str) ~= "string" then
        error("invalid argument #1 to 'FormatString' (string expected)");
      end;
      return formatString(str);
    end;
    
    function Serializer.UpdateConfig(options) 
      Assert(Type(options) == "table", "invalid argument #1 to 'UpdateConfig' (table expected)");
      config.spaces = options.spaces or 4;
      config.highlighting = options.highlighting;
      Tab = rep(" ", config.spaces or 4);
    end;
end

local md5=(
	((crypt or syn) and (function(data)
        return (crypt and crypt.hash(data, "md5") or syn and syn.crypt.custom.hash("md5", data)):lower()
    end)) or function(data)
    local md5 = {
        _VERSION = "md5.lua 1.1.0",
        _DESCRIPTION = "MD5 computation in Lua (5.1-3, LuaJIT)",
        _URL = "https://github.com/kikito/md5.lua",
        _LICENSE = [[
			MIT LICENSE

			Copyright (c) 2013 Enrique García Cota + Adam Baldwin + hanzao + Equi 4 Software

			Permission is hereby granted, free of charge, to any person obtaining a
			copy of this software and associated documentation files (the
			"Software"), to deal in the Software without restriction, including
			without limitation the rights to use, copy, modify, merge, publish,
			distribute, sublicense, and/or sell copies of the Software, and to
			permit persons to whom the Software is furnished to do so, subject to
			the following conditions:

			The above copyright notice and this permission notice shall be included
			in all copies or substantial portions of the Software.

			THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
			OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
			MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
			IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
			CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
			TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
			SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
		  ]]
    }

    -- bit lib implementions

    local char, byte, format, rep, sub = string.char, string.byte, string.format, string.rep, string.sub
    local bit_or, bit_and, bit_not, bit_xor, bit_rshift, bit_lshift

    local ok_ffi, ffi

    bit_or, bit_and, bit_not, bit_xor, bit_rshift, bit_lshift =
        bit.bor,
        bit.band,
        bit.bnot,
        bit.bxor,
        bit.rshift,
        bit.lshift

    -- convert little-endian 32-bit int to a 4-char string
    local lei2str
    -- function is defined this way to allow full jit compilation (removing UCLO instruction in LuaJIT)
    lei2str = function(i)
        local f = function(s)
            return char(bit_and(bit_rshift(i, s), 255))
        end
        return f(0) .. f(8) .. f(16) .. f(24)
    end

    -- convert raw string to big-endian int
    local function str2bei(s)
        local v = 0
        for i = 1, #s do
            v = v * 256 + byte(s, i)
        end
        return v
    end

    -- convert raw string to little-endian int
    local str2lei

    str2lei = function(s)
        local v = 0
        for i = #s, 1, -1 do
            v = v * 256 + byte(s, i)
        end
        return v
    end

    -- cut up a string in little-endian ints of given size
    local function cut_le_str(s)
        return {
            str2lei(sub(s, 1, 4)),
            str2lei(sub(s, 5, 8)),
            str2lei(sub(s, 9, 12)),
            str2lei(sub(s, 13, 16)),
            str2lei(sub(s, 17, 20)),
            str2lei(sub(s, 21, 24)),
            str2lei(sub(s, 25, 28)),
            str2lei(sub(s, 29, 32)),
            str2lei(sub(s, 33, 36)),
            str2lei(sub(s, 37, 40)),
            str2lei(sub(s, 41, 44)),
            str2lei(sub(s, 45, 48)),
            str2lei(sub(s, 49, 52)),
            str2lei(sub(s, 53, 56)),
            str2lei(sub(s, 57, 60)),
            str2lei(sub(s, 61, 64))
        }
    end

    -- An MD5 mplementation in Lua, requires bitlib (hacked to use LuaBit from above, ugh)
    -- 10/02/2001 jcw@equi4.com

    local CONSTS = {
        0xd76aa478,
        0xe8c7b756,
        0x242070db,
        0xc1bdceee,
        0xf57c0faf,
        0x4787c62a,
        0xa8304613,
        0xfd469501,
        0x698098d8,
        0x8b44f7af,
        0xffff5bb1,
        0x895cd7be,
        0x6b901122,
        0xfd987193,
        0xa679438e,
        0x49b40821,
        0xf61e2562,
        0xc040b340,
        0x265e5a51,
        0xe9b6c7aa,
        0xd62f105d,
        0x02441453,
        0xd8a1e681,
        0xe7d3fbc8,
        0x21e1cde6,
        0xc33707d6,
        0xf4d50d87,
        0x455a14ed,
        0xa9e3e905,
        0xfcefa3f8,
        0x676f02d9,
        0x8d2a4c8a,
        0xfffa3942,
        0x8771f681,
        0x6d9d6122,
        0xfde5380c,
        0xa4beea44,
        0x4bdecfa9,
        0xf6bb4b60,
        0xbebfbc70,
        0x289b7ec6,
        0xeaa127fa,
        0xd4ef3085,
        0x04881d05,
        0xd9d4d039,
        0xe6db99e5,
        0x1fa27cf8,
        0xc4ac5665,
        0xf4292244,
        0x432aff97,
        0xab9423a7,
        0xfc93a039,
        0x655b59c3,
        0x8f0ccc92,
        0xffeff47d,
        0x85845dd1,
        0x6fa87e4f,
        0xfe2ce6e0,
        0xa3014314,
        0x4e0811a1,
        0xf7537e82,
        0xbd3af235,
        0x2ad7d2bb,
        0xeb86d391,
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476
    }

    local f = function(x, y, z)
        return bit_or(bit_and(x, y), bit_and(-x - 1, z))
    end
    local g = function(x, y, z)
        return bit_or(bit_and(x, z), bit_and(y, -z - 1))
    end
    local h = function(x, y, z)
        return bit_xor(x, bit_xor(y, z))
    end
    local i = function(x, y, z)
        return bit_xor(y, bit_or(x, -z - 1))
    end
    local z = function(ff, a, b, c, d, x, s, ac)
        a = bit_and(a + ff(b, c, d) + x + ac, 0xFFFFFFFF)
        -- be *very* careful that left shift does not cause rounding!
        return bit_or(bit_lshift(bit_and(a, bit_rshift(0xFFFFFFFF, s)), s), bit_rshift(a, 32 - s)) + b
    end

    local function transform(A, B, C, D, X)
        local a, b, c, d = A, B, C, D
        local t = CONSTS

        a = z(f, a, b, c, d, X[0], 7, t[1])
        d = z(f, d, a, b, c, X[1], 12, t[2])
        c = z(f, c, d, a, b, X[2], 17, t[3])
        b = z(f, b, c, d, a, X[3], 22, t[4])
        a = z(f, a, b, c, d, X[4], 7, t[5])
        d = z(f, d, a, b, c, X[5], 12, t[6])
        c = z(f, c, d, a, b, X[6], 17, t[7])
        b = z(f, b, c, d, a, X[7], 22, t[8])
        a = z(f, a, b, c, d, X[8], 7, t[9])
        d = z(f, d, a, b, c, X[9], 12, t[10])
        c = z(f, c, d, a, b, X[10], 17, t[11])
        b = z(f, b, c, d, a, X[11], 22, t[12])
        a = z(f, a, b, c, d, X[12], 7, t[13])
        d = z(f, d, a, b, c, X[13], 12, t[14])
        c = z(f, c, d, a, b, X[14], 17, t[15])
        b = z(f, b, c, d, a, X[15], 22, t[16])

        a = z(g, a, b, c, d, X[1], 5, t[17])
        d = z(g, d, a, b, c, X[6], 9, t[18])
        c = z(g, c, d, a, b, X[11], 14, t[19])
        b = z(g, b, c, d, a, X[0], 20, t[20])
        a = z(g, a, b, c, d, X[5], 5, t[21])
        d = z(g, d, a, b, c, X[10], 9, t[22])
        c = z(g, c, d, a, b, X[15], 14, t[23])
        b = z(g, b, c, d, a, X[4], 20, t[24])
        a = z(g, a, b, c, d, X[9], 5, t[25])
        d = z(g, d, a, b, c, X[14], 9, t[26])
        c = z(g, c, d, a, b, X[3], 14, t[27])
        b = z(g, b, c, d, a, X[8], 20, t[28])
        a = z(g, a, b, c, d, X[13], 5, t[29])
        d = z(g, d, a, b, c, X[2], 9, t[30])
        c = z(g, c, d, a, b, X[7], 14, t[31])
        b = z(g, b, c, d, a, X[12], 20, t[32])

        a = z(h, a, b, c, d, X[5], 4, t[33])
        d = z(h, d, a, b, c, X[8], 11, t[34])
        c = z(h, c, d, a, b, X[11], 16, t[35])
        b = z(h, b, c, d, a, X[14], 23, t[36])
        a = z(h, a, b, c, d, X[1], 4, t[37])
        d = z(h, d, a, b, c, X[4], 11, t[38])
        c = z(h, c, d, a, b, X[7], 16, t[39])
        b = z(h, b, c, d, a, X[10], 23, t[40])
        a = z(h, a, b, c, d, X[13], 4, t[41])
        d = z(h, d, a, b, c, X[0], 11, t[42])
        c = z(h, c, d, a, b, X[3], 16, t[43])
        b = z(h, b, c, d, a, X[6], 23, t[44])
        a = z(h, a, b, c, d, X[9], 4, t[45])
        d = z(h, d, a, b, c, X[12], 11, t[46])
        c = z(h, c, d, a, b, X[15], 16, t[47])
        b = z(h, b, c, d, a, X[2], 23, t[48])

        a = z(i, a, b, c, d, X[0], 6, t[49])
        d = z(i, d, a, b, c, X[7], 10, t[50])
        c = z(i, c, d, a, b, X[14], 15, t[51])
        b = z(i, b, c, d, a, X[5], 21, t[52])
        a = z(i, a, b, c, d, X[12], 6, t[53])
        d = z(i, d, a, b, c, X[3], 10, t[54])
        c = z(i, c, d, a, b, X[10], 15, t[55])
        b = z(i, b, c, d, a, X[1], 21, t[56])
        a = z(i, a, b, c, d, X[8], 6, t[57])
        d = z(i, d, a, b, c, X[15], 10, t[58])
        c = z(i, c, d, a, b, X[6], 15, t[59])
        b = z(i, b, c, d, a, X[13], 21, t[60])
        a = z(i, a, b, c, d, X[4], 6, t[61])
        d = z(i, d, a, b, c, X[11], 10, t[62])
        c = z(i, c, d, a, b, X[2], 15, t[63])
        b = z(i, b, c, d, a, X[9], 21, t[64])

        return bit_and(A + a, 0xFFFFFFFF), bit_and(B + b, 0xFFFFFFFF), bit_and(C + c, 0xFFFFFFFF), bit_and(
            D + d,
            0xFFFFFFFF
        )
    end

    ----------------------------------------------------------------

    local function md5_update(self, s)
        self.pos = self.pos + #s
        s = self.buf .. s
        for ii = 1, #s - 63, 64 do
            local X = cut_le_str(sub(s, ii, ii + 63))
            assert(#X == 16)
            X[0] = table.remove(X, 1) -- zero based!
            self.a, self.b, self.c, self.d = transform(self.a, self.b, self.c, self.d, X)
        end
        self.buf = sub(s, math.floor(#s / 64) * 64 + 1, #s)
        return self
    end

    local function md5_finish(self)
        local msgLen = self.pos
        local padLen = 56 - msgLen % 64

        if msgLen % 64 > 56 then
            padLen = padLen + 64
        end

        if padLen == 0 then
            padLen = 64
        end

        local s =
            char(128) ..
            rep(char(0), padLen - 1) ..
                lei2str(bit_and(8 * msgLen, 0xFFFFFFFF)) .. lei2str(math.floor(msgLen / 0x20000000))
        md5_update(self, s)

        assert(self.pos % 64 == 0)
        return lei2str(self.a) .. lei2str(self.b) .. lei2str(self.c) .. lei2str(self.d)
    end

    ----------------------------------------------------------------

    function md5.new()
        return {
            a = CONSTS[65],
            b = CONSTS[66],
            c = CONSTS[67],
            d = CONSTS[68],
            pos = 0,
            buf = "",
            update = md5_update,
            finish = md5_finish
        }
    end

    function md5.tohex(s)
        return format(
            "%08x%08x%08x%08x",
            str2bei(sub(s, 1, 4)),
            str2bei(sub(s, 5, 8)),
            str2bei(sub(s, 9, 12)),
            str2bei(sub(s, 13, 16))
        )
    end

    function md5.sum(s)
        return md5.new():update(s):finish()
    end

    function md5.sumhexa(s)
        return md5.tohex(md5.sum(s))
    end

    return md5.sumhexa(data)
end)

local base64=[=[
	(
		((crypt or syn or Krnl or fluxus) and (function(data)
			local base64={}
			function base64.encode(data)
				return (crypt and crypt.base64encode or
				syn and syn.crypt.base64.encode or
				Krnl and Krnl.Base64.Encode or
				fluxus and fluxus.crypt.base64.encode)(data)
			end;
			
			function base64.decode(data)
				return (crypt and crypt.base64decode or
				syn and syn.crypt.base64.decode or
				Krnl and Krnl.Base64.Decode or
				fluxus and fluxus.crypt.base64.decode)(data)
			end;
			
			return base64.%s
		end)())
		or
		(function()
			--author: Ilya Kolbin (iskolbin@gmail.com)
			--url: github.com/iskolbin/lbase64

			local base64 = {}

			local extract = bit32 and bit32.extract or bit and (function( v, from, width )
				return bit.band( bit.rshift( v, from ), bit.lshift( 1, width ) - 1 )
			end) or (function( v, from, width )
				local w = 0
				local flag = 2^from
				for i = 0, width-1 do
					local flag2 = flag + flag
					if v %% flag2 >= flag then
						w = w + 2^i
					end
					flag = flag2
				end
				return w
			end)

			function base64.makeencoder( s62, s63, spad )
				local encoder = {}
				for b64code, char in pairs{[0]='A','B','C','D','E','F','G','H','I','J',
					'K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y',
					'Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n',
					'o','p','q','r','s','t','u','v','w','x','y','z','0','1','2',
					'3','4','5','6','7','8','9',s62 or '+',s63 or'/',spad or'='} do
					encoder[b64code] = char:byte()
				end
				return encoder
			end

			function base64.makedecoder( s62, s63, spad )
				local decoder = {}
				for b64code, charcode in pairs( base64.makeencoder( s62, s63, spad )) do
					decoder[charcode] = b64code
				end
				return decoder
			end

			local DEFAULT_ENCODER = base64.makeencoder()
			local DEFAULT_DECODER = base64.makedecoder()

			local char, concat = string.char, table.concat

			function base64.encode( str, encoder, usecaching )
				encoder = encoder or DEFAULT_ENCODER
				local t, k, n = {}, 1, #str
				local lastn = n %% 3
				local cache = {}
				for i = 1, n-lastn, 3 do
					local a, b, c = str:byte( i, i+2 )
					local v = a*0x10000 + b*0x100 + c
					local s
					if usecaching then
						s = cache[v]
						if not s then
							s = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[extract(v,0,6)])
							cache[v] = s
						end
					else
						s = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[extract(v,0,6)])
					end
					t[k] = s
					k = k + 1
				end
				if lastn == 2 then
					local a, b = str:byte( n-1, n )
					local v = a*0x10000 + b*0x100
					t[k] = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[extract(v,6,6)], encoder[64])
				elseif lastn == 1 then
					local v = str:byte( n )*0x10000
					t[k] = char(encoder[extract(v,18,6)], encoder[extract(v,12,6)], encoder[64], encoder[64])
				end
				return concat( t )
			end

			function base64.decode( b64, decoder, usecaching )
				decoder = decoder or DEFAULT_DECODER
				local pattern = '[^%%w%%+%%/%%=]'
				if decoder then
					local s62, s63
					for charcode, b64code in pairs( decoder ) do
						if b64code == 62 then s62 = charcode
						elseif b64code == 63 then s63 = charcode
						end
					end
					pattern = ('[^%%%%w%%%%%%s%%%%%%s%%%%=]'):format( char(s62), char(s63) )
				end
				b64 = b64:gsub( pattern, '' )
				local cache = usecaching and {}
				local t, k = {}, 1
				local n = #b64
				local padding = b64:sub(-2) == '==' and 2 or b64:sub(-1) == '=' and 1 or 0
				for i = 1, padding > 0 and n-4 or n, 4 do
					local a, b, c, d = b64:byte( i, i+3 )
					local s
					if usecaching then
						local v0 = a*0x1000000 + b*0x10000 + c*0x100 + d
						s = cache[v0]
						if not s then
							local v = decoder[a]*0x40000 + decoder[b]*0x1000 + decoder[c]*0x40 + decoder[d]
							s = char( extract(v,16,8), extract(v,8,8), extract(v,0,8))
							cache[v0] = s
						end
					else
						local v = decoder[a]*0x40000 + decoder[b]*0x1000 + decoder[c]*0x40 + decoder[d]
						s = char( extract(v,16,8), extract(v,8,8), extract(v,0,8))
					end
					t[k] = s
					k = k + 1
				end
				if padding == 1 then
					local a, b, c = b64:byte( n-3, n-1 )
					local v = decoder[a]*0x40000 + decoder[b]*0x1000 + decoder[c]*0x40
					t[k] = char( extract(v,16,8), extract(v,8,8))
				elseif padding == 2 then
					local a, b = b64:byte( n-3, n-2 )
					local v = decoder[a]*0x40000 + decoder[b]*0x1000
					t[k] = char( extract(v,16,8))
				end
				return concat( t )
			end

			return base64.%s
		end)()
	)]=]

local main=[=[
return (function(tbl,base64decode,makesfolder)
	local data={}
	makesfolder();
	for _,item in pairs(tbl) do
		local path="HUBWD/bin/" .. item["path"]
		if not(isfile(path)) then
			writefile(path,base64decode(item["content"]));
		end;
		data[path]=item["md5"]
	end;
	writefile("HUBWD/bin/%s/data/checksums.json",game:GetService("HttpService"):JSONEncode(data));
end)(
%s,
%s,
	(function()
		local file="%s";
		local list={
			"HUBWD";
			"HUBWD/bin";
			"HUBWD/bin/" .. file;
			"HUBWD/bin/" .. file .. "/lib";
			"HUBWD/bin/" .. file .. "/data";
			"HUBWD/bin/" .. file .. "/services";
		};
		
		for _,folder in pairs(list) do
			if not(isfolder(folder)) then
				makefolder(folder)
			end;
		end;
	end)
)
]=];

local bypass,exec=[=[
local lkhubLink = "https://lkhub.net/"
local leoKholYtLink = "https://raw.githubusercontent.com/LeoKholYt/"
local directorylink = "HUBWD/bin/lkhub/"

local list_json = game:GetService("HttpService"):JSONDecode(readfile(directorylink .. "data/list.json"))

local smatch=string.match

local httpGetLinks = {
	[lkhubLink .. "api/check.php"] = "Whitelisted", --Bypass Key
	[lkhubLink .. "s/loader.lua"] = directorylink .. "lib/loader.lua",

	--data
	[leoKholYtLink .. "lkhub/main/list.json"] = directorylink .. "data/list.json",
	[leoKholYtLink .. "lkhub/main/lol.json"] = directorylink .. "data/lol.lua",

	--lib
	[leoKholYtLink .. "roblox/main/discord_lib_mod.lua"] = directorylink .. "lib/discord_lib_mod.lua",
	[lkhubLink .. "s/ESP.lua"] = directorylink .. "lib/ESP.lua",
	[leoKholYtLink .. "lkhub/main/esp.lua"] = directorylink .. "lib/esp_1.lua",
	[leoKholYtLink .. "roblox/main/esp.lua"] = directorylink .. "lib/esp_2.lua",
	[leoKholYtLink .. "uilibs/main/finity.lua"] = directorylink .. "lib/finity.lua",
	[lkhubLink .. "s/lib.lua"] = directorylink .. "lib/lib.lua",
	[leoKholYtLink .. "roblox/main/lk_serverhop.lua"] = directorylink .. "lib/lk_serverhop.lua",
	[lkhubLink .. "s/LKHUB_Module.lua"] = directorylink .. "services/LKHUB_Module.lua",

	--services
	[lkhubLink .. "s/universal.lua"] = directorylink .. "services/universal.lua"
}
	
for i, data in pairs(list_json) do
	if data["s"] and smatch(data["s"], "%.lua$") then
		httpGetLinks[lkhubLink .. "s/" .. data["s"]] = directorylink .. "services/" .. data["s"]
	end
end

local oldHttpGet;oldHttpGet = hookfunction(game.HttpGet, function(method, url, ...)
	local urlFilter=url:gsub("%?key=.+", ""):gsub("^http://", "https://")
	local override = httpGetLinks[urlFilter]
	if override then
		if smatch(override, "^HUBWD/bin/")then
			if smatch(override, "%.json$") then
				return readfile(override)
			end;
			return loadfile(override)()
		end
		return override
	end
	return oldHttpGet(method, url, ...)
end)

--Anti lkhub
local oldReadfile;oldReadfile = hookfunction(readfile, function(data,...)
    if data == "lkhub_key.txt" then
        return "Invalid Key: Please contact support and say 'I love bananas' to get a new one."
    end;
    return oldReadfile(data,...)
end);

local oldMakefolder;oldMakefolder = hookfunction(makefolder, function(data,...)
    if data:match("^lkhub") then
        return
    end;
    return oldMakefolder(data,...)
end);

local oldWritefile;oldWritefile = hookfunction(writefile, function(data,...)
    if data:match("^lkhub") then
        return
    end;
    return oldWritefile(data,...)
end);
]=],[=[
loadfile(
	"HUBWD/bin/lkhub/lib/loader.lua"
)([[
--Just like a delicious coffee, a good exploit script should be strong and resilient. Unfortunately, lkhub is neither of those things. It's like drinking dirty water - no flavor, no benefits, and no safety.

--LKHub key system:
if "lkhub"=="lkhub" then
	print("LKHub is like a castle without walls - easy to enter and with no protection whatsoever.");
	return;
end
]]);
]=]

local file="lkhub"
local base64encode=loadstring('return '..base64:format("encode","encode"))()
local base64decode=base64:format("decode","decode");

local ignore = { "compact.lua", "installer.lua", "loaded.lua" }

local function shouldBlockFolder(file: string)
    local fileName = file:match("[^/\\]+$")
    for _, item in pairs(ignore) do
        if item == fileName then
            return false
        end
    end
    return true
end

local function listFilesRecursively(folderPath: table, fileNames: table)
    fileNames = fileNames or {}
    for _, filePath in ipairs(listfiles(folderPath)) do
        local Path=filePath:gsub("\\", "/")
        if isfolder(filePath) then
            listFilesRecursively(filePath, fileNames)
        elseif isfile(filePath) and shouldBlockFolder(filePath) then
            local content=readfile(filePath)
            table.insert(fileNames, {
                ["path"]=Path;
                ["content"]=base64encode(content);
                ["md5"]=md5(content);
            })
        end
    end
    return fileNames
end

--Finish

local tbl=listFilesRecursively(file)do --Manual
    function indent(str)
        local result = ""
        for line in string.gmatch(str, "[^\r\n]+") do
            result = result .. "\t" .. line .. "\n"
        end
        return result:sub(1, -2)
      end
    table.insert(tbl,{
        ["path"]=file.."/bypass.lua";
        ["content"]=base64encode(bypass);
        ["md5"]=md5(bypass);
    });
    table.insert(tbl,{
        ["path"]=file.."/loaded.lua";
        ["content"]=base64encode(exec);
        ["md5"]=md5(exec);
    });
    tbl=indent(Serializer.FormatArguments(tbl))
end;

writefile(file.."/installer.lua",main:format(
    file,
    tbl,
    base64decode,
    file
))