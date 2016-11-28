require("lockbox").insecure();

local Stream = require("lockbox.util.stream");
local Array = require("lockbox.util.array");

local String = require("string");
local Bit = require("lockbox.util.bit");
local Math = require("math");

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;


--NOTE: TEA is endian-dependent!
--The spec does not seem to specify which to use.
--It looks like most implementations use big-endian
local bytes2word = function(b0,b1,b2,b3)
	local i = b0; i = LSHIFT(i,8);
	i = OR(i,b1); i = LSHIFT(i,8);
	i = OR(i,b2); i = LSHIFT(i,8);
	i = OR(i,b3);
	return i;
end

local word2bytes = function(word)
	local b0,b1,b2,b3;
	b3 = AND(word,0xFF); word = RSHIFT(word,8);
	b2 = AND(word,0xFF); word = RSHIFT(word,8);
	b1 = AND(word,0xFF); word = RSHIFT(word,8);
	b0 = AND(word,0xFF);
	return b0,b1,b2,b3;
end

local TEA = {};

TEA.blockSize = 8;

TEA.encrypt = function(key,data)
	local y = bytes2word(data[1],data[2],data[3],data[4]);
	local z = bytes2word(data[5],data[6],data[7],data[8]);
	local delta = 0x9e3779b9;
	local sum = 0;

	local k0 = bytes2word(key[ 1],key[ 2],key[ 3],key[ 4]);
	local k1 = bytes2word(key[ 5],key[ 6],key[ 7],key[ 8]);
	local k2 = bytes2word(key[ 9],key[10],key[11],key[12]);
	local k3 = bytes2word(key[13],key[14],key[15],key[16]);

	for i = 1,32 do
		local temp;

		sum = AND(sum + delta, 0xFFFFFFFF);

		temp = z+sum;
		temp = XOR(temp,LSHIFT(z,4)+k0);
		temp = XOR(temp,RSHIFT(z,5)+k1);
		y = AND(y + temp, 0xFFFFFFFF);

		temp = y+sum;
		temp = XOR(temp,LSHIFT(y,4)+k2);
		temp = XOR(temp,RSHIFT(y,5)+k3);
		z = AND( z + temp, 0xFFFFFFFF);
	end

	local out = {};

	out[1],out[2],out[3],out[4] = word2bytes(y);
	out[5],out[6],out[7],out[8] = word2bytes(z);

	return out;
end

TEA.decrypt = function(key,data)
	local y = bytes2word(data[1],data[2],data[3],data[4]);
	local z = bytes2word(data[5],data[6],data[7],data[8]);

	local delta = 0x9e3779b9;
	local sum = 0xc6ef3720; --AND(delta*32,0xFFFFFFFF);

	local k0 = bytes2word(key[ 1],key[ 2],key[ 3],key[ 4]);
	local k1 = bytes2word(key[ 5],key[ 6],key[ 7],key[ 8]);
	local k2 = bytes2word(key[ 9],key[10],key[11],key[12]);
	local k3 = bytes2word(key[13],key[14],key[15],key[16]);

	for i = 1,32 do
		local temp;

		temp = y+sum;
		temp = XOR(temp,LSHIFT(y,4)+k2);
		temp = XOR(temp,RSHIFT(y,5)+k3);
		z = AND(z + 0x100000000 - temp,0xFFFFFFFF);

		temp = z+sum;
		temp = XOR(temp,LSHIFT(z,4)+k0);
		temp = XOR(temp,RSHIFT(z,5)+k1);
		y = AND(y + 0x100000000 - temp,0xFFFFFFFF);

		sum = AND(sum + 0x100000000 - delta,0xFFFFFFFF);
	end

	local out = {};

	out[1],out[2],out[3],out[4] = word2bytes(y);
	out[5],out[6],out[7],out[8] = word2bytes(z);

	return out;
end

return TEA;
