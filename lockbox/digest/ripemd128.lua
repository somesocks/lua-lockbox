require("lockbox").insecure();

local Bit = require("lockbox.util.bit");
local String = require("string");
local Math = require("math");
local Queue = require("lockbox.util.queue");

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;

--RIPEMD128 is little-endian
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

local F = function(x,y,z) return XOR(x, XOR(y,z)); end
local G = function(x,y,z) return OR(AND(x,y), AND(NOT(x),z)); end
local H = function(x,y,z) return XOR(OR(x,NOT(y)),z); end
local I = function(x,y,z) return OR(AND(x,z),AND(y,NOT(z))); end

local FF = function(a,b,c,d,x,s)
	a = a + F(b,c,d) + x;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local GG = function(a,b,c,d,x,s)
	a = a + G(b,c,d) + x + 0x5a827999;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local HH = function(a,b,c,d,x,s)
	a = a + H(b,c,d) + x + 0x6ed9eba1;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local II = function(a,b,c,d,x,s)
	a = a + I(b,c,d) + x + 0x8f1bbcdc;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end


local FFF = function(a,b,c,d,x,s)
	a = a + F(b,c,d) + x;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local GGG = function(a,b,c,d,x,s)
	a = a + G(b,c,d) + x + 0x6d703ef3;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local HHH = function(a,b,c,d,x,s)
	a = a + H(b,c,d) + x + 0x5c4dd124;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local III = function(a,b,c,d,x,s)
	a = a + I(b,c,d) + x + 0x50a28be6;
	a = LROT(a,s);
	a = AND(a, 0xFFFFFFFF);
	return a;
end

local RIPEMD128 = function()

	local queue = Queue();

	local A = 0x67452301;
	local B = 0xefcdab89;
	local C = 0x98badcfe;
	local D = 0x10325476;

	local public = {};

	local processBlock = function()
		local aa,bb,cc,dd = A,B,C,D;
		local aaa,bbb,ccc,ddd = A,B,C,D;

		local X = {};

		for i=0,15 do
			X[i] = bytes2word(queue.pop(),queue.pop(),queue.pop(),queue.pop());
		end

		aa = FF(aa, bb, cc, dd, X[ 0], 11);
		dd = FF(dd, aa, bb, cc, X[ 1], 14);
		cc = FF(cc, dd, aa, bb, X[ 2], 15);
		bb = FF(bb, cc, dd, aa, X[ 3], 12);
		aa = FF(aa, bb, cc, dd, X[ 4],  5);
		dd = FF(dd, aa, bb, cc, X[ 5],  8);
		cc = FF(cc, dd, aa, bb, X[ 6],  7);
		bb = FF(bb, cc, dd, aa, X[ 7],  9);
		aa = FF(aa, bb, cc, dd, X[ 8], 11);
		dd = FF(dd, aa, bb, cc, X[ 9], 13);
		cc = FF(cc, dd, aa, bb, X[10], 14);
		bb = FF(bb, cc, dd, aa, X[11], 15);
		aa = FF(aa, bb, cc, dd, X[12],  6);
		dd = FF(dd, aa, bb, cc, X[13],  7);
		cc = FF(cc, dd, aa, bb, X[14],  9);
		bb = FF(bb, cc, dd, aa, X[15],  8);

		aa = GG(aa, bb, cc, dd, X[ 7],  7);
		dd = GG(dd, aa, bb, cc, X[ 4],  6);
		cc = GG(cc, dd, aa, bb, X[13],  8);
		bb = GG(bb, cc, dd, aa, X[ 1], 13);
		aa = GG(aa, bb, cc, dd, X[10], 11);
		dd = GG(dd, aa, bb, cc, X[ 6],  9);
		cc = GG(cc, dd, aa, bb, X[15],  7);
		bb = GG(bb, cc, dd, aa, X[ 3], 15);
		aa = GG(aa, bb, cc, dd, X[12],  7);
		dd = GG(dd, aa, bb, cc, X[ 0], 12);
		cc = GG(cc, dd, aa, bb, X[ 9], 15);
		bb = GG(bb, cc, dd, aa, X[ 5],  9);
		aa = GG(aa, bb, cc, dd, X[ 2], 11);
		dd = GG(dd, aa, bb, cc, X[14],  7);
		cc = GG(cc, dd, aa, bb, X[11], 13);
		bb = GG(bb, cc, dd, aa, X[ 8], 12);

		aa = HH(aa, bb, cc, dd, X[ 3], 11);
		dd = HH(dd, aa, bb, cc, X[10], 13);
		cc = HH(cc, dd, aa, bb, X[14],  6);
		bb = HH(bb, cc, dd, aa, X[ 4],  7);
		aa = HH(aa, bb, cc, dd, X[ 9], 14);
		dd = HH(dd, aa, bb, cc, X[15],  9);
		cc = HH(cc, dd, aa, bb, X[ 8], 13);
		bb = HH(bb, cc, dd, aa, X[ 1], 15);
		aa = HH(aa, bb, cc, dd, X[ 2], 14);
		dd = HH(dd, aa, bb, cc, X[ 7],  8);
		cc = HH(cc, dd, aa, bb, X[ 0], 13);
		bb = HH(bb, cc, dd, aa, X[ 6],  6);
		aa = HH(aa, bb, cc, dd, X[13],  5);
		dd = HH(dd, aa, bb, cc, X[11], 12);
		cc = HH(cc, dd, aa, bb, X[ 5],  7);
		bb = HH(bb, cc, dd, aa, X[12],  5);

		aa = II(aa, bb, cc, dd, X[ 1], 11);
		dd = II(dd, aa, bb, cc, X[ 9], 12);
		cc = II(cc, dd, aa, bb, X[11], 14);
		bb = II(bb, cc, dd, aa, X[10], 15);
		aa = II(aa, bb, cc, dd, X[ 0], 14);
		dd = II(dd, aa, bb, cc, X[ 8], 15);
		cc = II(cc, dd, aa, bb, X[12],  9);
		bb = II(bb, cc, dd, aa, X[ 4],  8);
		aa = II(aa, bb, cc, dd, X[13],  9);
		dd = II(dd, aa, bb, cc, X[ 3], 14);
		cc = II(cc, dd, aa, bb, X[ 7],  5);
		bb = II(bb, cc, dd, aa, X[15],  6);
		aa = II(aa, bb, cc, dd, X[14],  8);
		dd = II(dd, aa, bb, cc, X[ 5],  6);
		cc = II(cc, dd, aa, bb, X[ 6],  5);
		bb = II(bb, cc, dd, aa, X[ 2], 12);

		aaa = III(aaa, bbb, ccc, ddd, X[ 5],  8);
		ddd = III(ddd, aaa, bbb, ccc, X[14],  9);
		ccc = III(ccc, ddd, aaa, bbb, X[ 7],  9);
		bbb = III(bbb, ccc, ddd, aaa, X[ 0], 11);
		aaa = III(aaa, bbb, ccc, ddd, X[ 9], 13);
		ddd = III(ddd, aaa, bbb, ccc, X[ 2], 15);
		ccc = III(ccc, ddd, aaa, bbb, X[11], 15);
		bbb = III(bbb, ccc, ddd, aaa, X[ 4],  5);
		aaa = III(aaa, bbb, ccc, ddd, X[13],  7);
		ddd = III(ddd, aaa, bbb, ccc, X[ 6],  7);
		ccc = III(ccc, ddd, aaa, bbb, X[15],  8);
		bbb = III(bbb, ccc, ddd, aaa, X[ 8], 11);
		aaa = III(aaa, bbb, ccc, ddd, X[ 1], 14);
		ddd = III(ddd, aaa, bbb, ccc, X[10], 14);
		ccc = III(ccc, ddd, aaa, bbb, X[ 3], 12);
		bbb = III(bbb, ccc, ddd, aaa, X[12],  6);

		aaa = HHH(aaa, bbb, ccc, ddd, X[ 6],  9);
		ddd = HHH(ddd, aaa, bbb, ccc, X[11], 13);
		ccc = HHH(ccc, ddd, aaa, bbb, X[ 3], 15);
		bbb = HHH(bbb, ccc, ddd, aaa, X[ 7],  7);
		aaa = HHH(aaa, bbb, ccc, ddd, X[ 0], 12);
		ddd = HHH(ddd, aaa, bbb, ccc, X[13],  8);
		ccc = HHH(ccc, ddd, aaa, bbb, X[ 5],  9);
		bbb = HHH(bbb, ccc, ddd, aaa, X[10], 11);
		aaa = HHH(aaa, bbb, ccc, ddd, X[14],  7);
		ddd = HHH(ddd, aaa, bbb, ccc, X[15],  7);
		ccc = HHH(ccc, ddd, aaa, bbb, X[ 8], 12);
		bbb = HHH(bbb, ccc, ddd, aaa, X[12],  7);
		aaa = HHH(aaa, bbb, ccc, ddd, X[ 4],  6);
		ddd = HHH(ddd, aaa, bbb, ccc, X[ 9], 15);
		ccc = HHH(ccc, ddd, aaa, bbb, X[ 1], 13);
		bbb = HHH(bbb, ccc, ddd, aaa, X[ 2], 11);

		aaa = GGG(aaa, bbb, ccc, ddd, X[15],  9);
		ddd = GGG(ddd, aaa, bbb, ccc, X[ 5],  7);
		ccc = GGG(ccc, ddd, aaa, bbb, X[ 1], 15);
		bbb = GGG(bbb, ccc, ddd, aaa, X[ 3], 11);
		aaa = GGG(aaa, bbb, ccc, ddd, X[ 7],  8);
		ddd = GGG(ddd, aaa, bbb, ccc, X[14],  6);
		ccc = GGG(ccc, ddd, aaa, bbb, X[ 6],  6);
		bbb = GGG(bbb, ccc, ddd, aaa, X[ 9], 14);
		aaa = GGG(aaa, bbb, ccc, ddd, X[11], 12);
		ddd = GGG(ddd, aaa, bbb, ccc, X[ 8], 13);
		ccc = GGG(ccc, ddd, aaa, bbb, X[12],  5);
		bbb = GGG(bbb, ccc, ddd, aaa, X[ 2], 14);
		aaa = GGG(aaa, bbb, ccc, ddd, X[10], 13);
		ddd = GGG(ddd, aaa, bbb, ccc, X[ 0], 13);
		ccc = GGG(ccc, ddd, aaa, bbb, X[ 4],  7);
		bbb = GGG(bbb, ccc, ddd, aaa, X[13],  5);

		aaa = FFF(aaa, bbb, ccc, ddd, X[ 8], 15);
		ddd = FFF(ddd, aaa, bbb, ccc, X[ 6],  5);
		ccc = FFF(ccc, ddd, aaa, bbb, X[ 4],  8);
		bbb = FFF(bbb, ccc, ddd, aaa, X[ 1], 11);
		aaa = FFF(aaa, bbb, ccc, ddd, X[ 3], 14);
		ddd = FFF(ddd, aaa, bbb, ccc, X[11], 14);
		ccc = FFF(ccc, ddd, aaa, bbb, X[15],  6);
		bbb = FFF(bbb, ccc, ddd, aaa, X[ 0], 14);
		aaa = FFF(aaa, bbb, ccc, ddd, X[ 5],  6);
		ddd = FFF(ddd, aaa, bbb, ccc, X[12],  9);
		ccc = FFF(ccc, ddd, aaa, bbb, X[ 2], 12);
		bbb = FFF(bbb, ccc, ddd, aaa, X[13],  9);
		aaa = FFF(aaa, bbb, ccc, ddd, X[ 9], 12);
		ddd = FFF(ddd, aaa, bbb, ccc, X[ 7],  5);
		ccc = FFF(ccc, ddd, aaa, bbb, X[10], 15);
		bbb = FFF(bbb, ccc, ddd, aaa, X[14],  8);


		A, B, C, D = AND(B + cc + ddd, 0xFFFFFFFF),
					 AND(C + dd + aaa, 0xFFFFFFFF),
					 AND(D + aa + bbb, 0xFFFFFFFF),
					 AND(A + bb + ccc, 0xFFFFFFFF);

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

		return { b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,
				b10,b11,b12,b13,b14,b15};
	end

	public.asHex = function()
		local  b0, b1, b2, b3 = word2bytes(A);
		local  b4, b5, b6, b7 = word2bytes(B);
		local  b8, b9,b10,b11 = word2bytes(C);
		local b12,b13,b14,b15 = word2bytes(D);

		local fmt = "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

		return String.format(fmt,
				 b0, b1, b2, b3, b4, b5, b6, b7, b8, b9,
				b10,b11,b12,b13,b14,b15);
	end

	return public;

end

return RIPEMD128;

