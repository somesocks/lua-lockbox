local String = require("string");
local Bit = require("lockbox.util.bit");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;


local SYMBOLS = {
[0]="A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P",
    "Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f",
    "g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v",
    "w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"};

local LOOKUP = {};

for k,v in pairs(SYMBOLS) do
	LOOKUP[k]=v;
	LOOKUP[v]=k;
end


local Base64 = {};

Base64.fromStream = function(stream)
	local bits = 0x00;
	local bitCount = 0;
	local base64 = {};

	local byte = stream();
	while byte ~= nil do
		bits = OR(LSHIFT(bits,8),byte);
		bitCount = bitCount + 8;
		while bitCount >= 6 do
			bitCount = bitCount - 6;
			local temp = RSHIFT(bits,bitCount);
			table.insert(base64,LOOKUP[temp]);
			bits = AND(bits,NOT(LSHIFT(0xFFFFFFFF,bitCount)));
		end
		byte = stream();
	end

	if (bitCount == 4) then
		bits = LSHIFT(bits,2);
		table.insert(base64,LOOKUP[bits]);
		table.insert(base64,"=");
	elseif (bitCount == 2) then
		bits = LSHIFT(bits,4);
		table.insert(base64,LOOKUP[bits]);
		table.insert(base64,"==");
	end

	return table.concat(base64,"");
end

Base64.fromArray = function(array)
	local bits = 0x00;
	local bitCount = 0;
	local base64 = {};

	local ind = 1;

	local byte = array[ind]; ind = ind + 1;
	while byte ~= nil do
		bits = OR(LSHIFT(bits,8),byte);
		bitCount = bitCount + 8;
		while bitCount >= 6 do
			bitCount = bitCount - 6;
			local temp = RSHIFT(bits,bitCount);
			table.insert(base64,LOOKUP[temp]);
			bits = AND(bits,NOT(LSHIFT(0xFFFFFFFF,bitCount)));
		end
		byte = array[ind]; ind = ind + 1;
	end

	if (bitCount == 4) then
		bits = LSHIFT(bits,2);
		table.insert(base64,LOOKUP[bits]);
		table.insert(base64,"=");
	elseif (bitCount == 2) then
		bits = LSHIFT(bits,4);
		table.insert(base64,LOOKUP[bits]);
		table.insert(base64,"==");
	end

	return table.concat(base64,"");
end

Base64.fromString = function(string)
	return Base64.fromArray(Array.fromString(string));
end



Base64.toStream = function(base64)
	return Stream.fromArray(Base64.toArray(base64));
end

Base64.toArray = function(base64)
	local bits = 0x00;
	local bitCount = 0;

	local bytes = {};

	for c in String.gmatch(base64,".") do
		if (c == "=") then
			bits = RSHIFT(bits,2); bitCount = bitCount - 2;
		else
			bits = LSHIFT(bits,6); bitCount = bitCount + 6;
			bits = OR(bits,LOOKUP[c]);
		end

		while(bitCount >= 8) do
			bitCount = bitCount - 8;
			local temp = RSHIFT(bits,bitCount);
			table.insert(bytes,temp);
			bits = AND(bits,NOT(LSHIFT(0xFFFFFFFF,bitCount)));
		end
	end

	return bytes;
end

Base64.toString = function(base64)
	local bits = 0x00;
	local bitCount = 0;

	local chars = {};

	for c in String.gmatch(base64,".") do
		if (c == "=") then
			bits = RSHIFT(bits,2); bitCount = bitCount - 2;
		else
			bits = LSHIFT(bits,6); bitCount = bitCount + 6;
			bits = OR(bits,LOOKUP[c]);
		end

		while(bitCount >= 8) do
			bitCount = bitCount - 8;
			local temp = RSHIFT(bits,bitCount);
			table.insert(chars,String.char(temp));
			bits = AND(bits,NOT(LSHIFT(0xFFFFFFFF,bitCount)));
		end
	end

	return table.concat(chars,"");
end

return Base64;
