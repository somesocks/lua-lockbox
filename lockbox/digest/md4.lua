require("lockbox").insecure();

local Bit = require("lockbox.util.bit");
local String = require("string");
local Math = require("math");
local Queue = require("lockbox.util.queue");

local SHIFT = {	3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,  3,  7, 11, 19,
				3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,  3,  5,  9, 13,
				3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15,  3,  9, 11, 15 };

local WORD = {	0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
				0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 13,
				3,  8,  4, 12,  2, 10,  6, 14,  1,  9,  5, 13,  3,  1,  7, 15 };

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;

--MD4 is little-endian
local bytes2word = function(b0,b1,b2,b3)
	local i = b3; i = LSHIFT(i,8);
	i = OR(i,b2); i = LSHIFT(i,8);
	i = OR(i,b1); i = LSHIFT(i,8);
	i = OR(i,b0);
	return i;
end

local word2bytes = function(word)
	local b0,b1,b2,b3;
	b0 = AND(word,0xFF); word = RSHIFT(word,8);
	b1 = AND(word,0xFF); word = RSHIFT(word,8);
	b2 = AND(word,0xFF); word = RSHIFT(word,8);
	b3 = AND(word,0xFF);
	return b0,b1,b2,b3;
end

local bytes2dword = function(b0,b1,b2,b3,b4,b5,b6,b7)
	local i = bytes2word(b0,b1,b2,b3);
	local j = bytes2word(b4,b5,b6,b7);
	return (j*0x100000000)+i;
end

local dword2bytes = function(i)
	local b4,b5,b6,b7 = word2bytes(Math.floor(i/0x100000000));
	local b0,b1,b2,b3 = word2bytes(i);
	return b0,b1,b2,b3,b4,b5,b6,b7;
end

local F = function(x,y,z) return OR(AND(x,y),AND(NOT(x),z)); end
local G = function(x,y,z) return OR(AND(x,y), OR(AND(x,z), AND(y,z))); end
local H = function(x,y,z) return XOR(x,XOR(y,z)); end


local MD4 = function()

	local queue = Queue();

	local A = 0x67452301;
	local B = 0xefcdab89;
	local C = 0x98badcfe;
	local D = 0x10325476;
	local public = {};

	local processBlock = function()
		local a = A;
		local b = B;
		local c = C;
		local d = D;

		local X = {};

		for i=0,15 do
			X[i] = bytes2word(queue.pop(),queue.pop(),queue.pop(),queue.pop());
		end

		a = LROT(a + F(b,c,d) + X[ 0], 3);
		d = LROT(d + F(a,b,c) + X[ 1], 7);
		c = LROT(c + F(d,a,b) + X[ 2],11);
		b = LROT(b + F(c,d,a) + X[ 3],19);

		a = LROT(a + F(b,c,d) + X[ 4], 3);
		d = LROT(d + F(a,b,c) + X[ 5], 7);
		c = LROT(c + F(d,a,b) + X[ 6],11);
		b = LROT(b + F(c,d,a) + X[ 7],19);

		a = LROT(a + F(b,c,d) + X[ 8], 3);
		d = LROT(d + F(a,b,c) + X[ 9], 7);
		c = LROT(c + F(d,a,b) + X[10],11);
		b = LROT(b + F(c,d,a) + X[11],19);

		a = LROT(a + F(b,c,d) + X[12], 3);
		d = LROT(d + F(a,b,c) + X[13], 7);
		c = LROT(c + F(d,a,b) + X[14],11);
		b = LROT(b + F(c,d,a) + X[15],19);


		a = LROT(a + G(b,c,d) + X[ 0] + 0x5A827999, 3);
		d = LROT(d + G(a,b,c) + X[ 4] + 0x5A827999, 5);
		c = LROT(c + G(d,a,b) + X[ 8] + 0x5A827999, 9);
		b = LROT(b + G(c,d,a) + X[12] + 0x5A827999,13);

		a = LROT(a + G(b,c,d) + X[ 1] + 0x5A827999, 3);
		d = LROT(d + G(a,b,c) + X[ 5] + 0x5A827999, 5);
		c = LROT(c + G(d,a,b) + X[ 9] + 0x5A827999, 9);
		b = LROT(b + G(c,d,a) + X[13] + 0x5A827999,13);

		a = LROT(a + G(b,c,d) + X[ 2] + 0x5A827999, 3);
		d = LROT(d + G(a,b,c) + X[ 6] + 0x5A827999, 5);
		c = LROT(c + G(d,a,b) + X[10] + 0x5A827999, 9);
		b = LROT(b + G(c,d,a) + X[14] + 0x5A827999,13);

		a = LROT(a + G(b,c,d) + X[ 3] + 0x5A827999, 3);
		d = LROT(d + G(a,b,c) + X[ 7] + 0x5A827999, 5);
		c = LROT(c + G(d,a,b) + X[11] + 0x5A827999, 9);
		b = LROT(b + G(c,d,a) + X[15] + 0x5A827999,13);


		a = LROT(a + H(b,c,d) + X[ 0] + 0x6ED9EBA1, 3);
		d = LROT(d + H(a,b,c) + X[ 8] + 0x6ED9EBA1, 9);
		c = LROT(c + H(d,a,b) + X[ 4] + 0x6ED9EBA1,11);
		b = LROT(b + H(c,d,a) + X[12] + 0x6ED9EBA1,15);

		a = LROT(a + H(b,c,d) + X[ 2] + 0x6ED9EBA1, 3);
		d = LROT(d + H(a,b,c) + X[10] + 0x6ED9EBA1, 9);
		c = LROT(c + H(d,a,b) + X[ 6] + 0x6ED9EBA1,11);
		b = LROT(b + H(c,d,a) + X[14] + 0x6ED9EBA1,15);

		a = LROT(a + H(b,c,d) + X[ 1] + 0x6ED9EBA1, 3);
		d = LROT(d + H(a,b,c) + X[ 9] + 0x6ED9EBA1, 9);
		c = LROT(c + H(d,a,b) + X[ 5] + 0x6ED9EBA1,11);
		b = LROT(b + H(c,d,a) + X[13] + 0x6ED9EBA1,15);

		a = LROT(a + H(b,c,d) + X[ 3] + 0x6ED9EBA1, 3);
		d = LROT(d + H(a,b,c) + X[11] + 0x6ED9EBA1, 9);
		c = LROT(c + H(d,a,b) + X[ 7] + 0x6ED9EBA1,11);
		b = LROT(b + H(c,d,a) + X[15] + 0x6ED9EBA1,15);


		A = AND(A + a, 0xFFFFFFFF);
		B = AND(B + b, 0xFFFFFFFF);
		C = AND(C + c, 0xFFFFFFFF);
		D = AND(D + d, 0xFFFFFFFF);
	end

	public.init = function()
		queue.reset();

		A = 0x67452301;
		B = 0xefcdab89;
		C = 0x98badcfe;
		D = 0x10325476;

		return public;
	end

	public.update = function(bytes)
		for b in bytes do
			queue.push(b);
			if(queue.size() >= 64) then processBlock(); end
		end

		return public;
	end

	public.finish = function()
		local bits = queue.getHead() * 8;

		queue.push(0x80);
		while ((queue.size()+7) % 64) < 63 do
			queue.push(0x00);
		end

		local b0,b1,b2,b3,b4,b5,b6,b7 = dword2bytes(bits);

		queue.push(b0);
		queue.push(b1);
		queue.push(b2);
		queue.push(b3);
		queue.push(b4);
		queue.push(b5);
		queue.push(b6);
		queue.push(b7);

		while queue.size() > 0 do
			processBlock();
		end

		return public;
	end

	public.asBytes = function()
		local  b0, b1, b2, b3 = word2bytes(A);
		local  b4, b5, b6, b7 = word2bytes(B);
		local  b8, b9,b10,b11 = word2bytes(C);
		local b12,b13,b14,b15 = word2bytes(D);

		return {b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15};
	end

	public.asHex = function()
		local  b0, b1, b2, b3 = word2bytes(A);
		local  b4, b5, b6, b7 = word2bytes(B);
		local  b8, b9,b10,b11 = word2bytes(C);
		local b12,b13,b14,b15 = word2bytes(D);

		return String.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15);
	end

	return public;

end

return MD4;
