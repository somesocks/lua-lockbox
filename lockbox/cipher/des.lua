require("lockbox").insecure();

local Stream = require("lockbox.util.stream");
local Array = require("lockbox.util.array");

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

local IN_P = {	58, 50, 42, 34, 26, 18, 10,  2,
				60, 52, 44, 36, 28, 20, 12,  4,
				62, 54, 46, 38, 30, 22, 14,  6,
				64, 56, 48, 40, 32, 24, 16,  8,
				57, 49, 41, 33, 25, 17,  9,  1,
				59, 51, 43, 35, 27, 19, 11,  3,
				61, 53, 45, 37, 29, 21, 13,  5,
				63, 55, 47, 39, 31, 23, 15,  7};

local OUT_P = {	40,  8, 48, 16, 56, 24, 64, 32,
				39,  7, 47, 15, 55, 23, 63, 31,
				38,  6, 46, 14, 54, 22, 62, 30,
				37,  5, 45, 13, 53, 21, 61, 29,
				36,  4, 44, 12, 52, 20, 60, 28,
				35,  3, 43, 11, 51, 19, 59, 27,
				34,  2, 42, 10, 50, 18, 58, 26,
				33,  1, 41,  9, 49, 17, 57, 25};

-- add 32 to each because we do the expansion on the full LR table, not just R
local EBIT = {	32+32,  1+32,  2+32,  3+32,  4+32,  5+32,  4+32,  5+32,  6+32,  7+32,  8+32,  9+32,
				 8+32,  9+32, 10+32, 11+32, 12+32, 13+32, 12+32, 13+32, 14+32, 15+32, 16+32, 17+32,
				16+32, 17+32, 18+32, 19+32, 20+32, 21+32, 20+32, 21+32, 22+32, 23+32, 24+32, 25+32,
				24+32, 25+32, 26+32, 27+32, 28+32, 29+32, 28+32, 29+32, 30+32, 31+32, 32+32,  1+32, };

local LR_SWAP = {	33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
					49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,
					 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,
					17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};

local PC1 = {	57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
				10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
				63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
				14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4};

local PC2 = {	14,17,11,24, 1, 5, 3,28,15, 6,21,10,
                23,19,12, 4,26, 8,16, 7,27,20,13, 2,
                41,52,31,37,47,55,30,40,51,45,33,48,
                44,49,39,56,34,53,46,42,50,36,29,32};

local KS1 = {	 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 1,
				30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,29};
local KS2 = KS1;

local KS3 = {	 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28, 1, 2,
				31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,29,30};

local KS4  = KS3;
local KS5  = KS3;
local KS6  = KS3;
local KS7  = KS3;
local KS8  = KS3;
local KS9  = KS1;
local KS10 = KS3;
local KS11 = KS3;
local KS12 = KS3;
local KS13 = KS3;
local KS14 = KS3;
local KS15 = KS3;
local KS16 = KS1;


local SIND1 = {    2,   3,   4,   5,   1,   6 };
local SIND2 = {  2+6, 3+6, 4+6, 5+6, 1+6, 6+6 };
local SIND3 = { 2+12,3+12,4+12,5+12,1+12,6+12 };
local SIND4 = { 2+18,3+18,4+18,5+18,1+18,6+18 };
local SIND5 = { 2+24,3+24,4+24,5+24,1+24,6+24 };
local SIND6 = { 2+30,3+30,4+30,5+30,1+30,6+30 };
local SIND7 = { 2+36,3+36,4+36,5+36,1+36,6+36 };
local SIND8 = { 2+42,3+42,4+42,5+42,1+42,6+42 };

local SBOX1 = {	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13};

local SBOX2 = {	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9};

local SBOX3 = {	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
				13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
				13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
				1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12};

local SBOX4 = {	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
				13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
				10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
				3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14};

local SBOX5 = {	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
				14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
				4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
				11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3};

local SBOX6 = {	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
				10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
				9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
				4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13};

local SBOX7 = {	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
				13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
				1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
				6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12};

local SBOX8 = {	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
				1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
				7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
				2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

local ROUND_P = {	16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
					 2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25};

local permute = Array.permute;

local unpackBytes = function(bytes)
	local bits = {};

	for k,b in pairs(bytes) do
		table.insert(bits,RSHIFT(AND(b,0x80),7));
		table.insert(bits,RSHIFT(AND(b,0x40),6));
		table.insert(bits,RSHIFT(AND(b,0x20),5));
		table.insert(bits,RSHIFT(AND(b,0x10),4));
		table.insert(bits,RSHIFT(AND(b,0x08),3));
		table.insert(bits,RSHIFT(AND(b,0x04),2));
		table.insert(bits,RSHIFT(AND(b,0x02),1));
		table.insert(bits,      AND(b,0x01)   );
	end

	return bits;
end

local packBytes = function(bits)
	local bytes = {}

	for k,v in pairs(bits) do
		local index = Math.floor((k-1)/8) + 1;
		local shift = 7-Math.fmod((k-1),8);

		local bit = bits[k];
		local byte = bytes[index];

		if not byte then byte = 0x00; end
		byte = OR(byte,LSHIFT(bit,shift));
		bytes[index] = byte;
	end

	return bytes;
end

local mix = function(LR,key)

	local ER = permute(LR,EBIT);

	for k,v in pairs(ER) do
		ER[k] = XOR(ER[k],key[k]);
	end

	local FRK = {};

	local S = 0x00;
	S = OR(S,ER[1]); S = LSHIFT(S,1);
	S = OR(S,ER[6]); S = LSHIFT(S,1);
	S = OR(S,ER[2]); S = LSHIFT(S,1);
	S = OR(S,ER[3]); S = LSHIFT(S,1);
	S = OR(S,ER[4]); S = LSHIFT(S,1);
	S = OR(S,ER[5]); S = S+1;
	S = SBOX1[S];

	FRK[1] = RSHIFT(AND(S,0x08),3);
	FRK[2] = RSHIFT(AND(S,0x04),2);
	FRK[3] = RSHIFT(AND(S,0x02),1);
	FRK[4] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+6]); S = LSHIFT(S,1);
	S = OR(S,ER[6+6]); S = LSHIFT(S,1);
	S = OR(S,ER[2+6]); S = LSHIFT(S,1);
	S = OR(S,ER[3+6]); S = LSHIFT(S,1);
	S = OR(S,ER[4+6]); S = LSHIFT(S,1);
	S = OR(S,ER[5+6]); S = S+1;
	S = SBOX2[S];

	FRK[5] = RSHIFT(AND(S,0x08),3);
	FRK[6] = RSHIFT(AND(S,0x04),2);
	FRK[7] = RSHIFT(AND(S,0x02),1);
	FRK[8] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+12]); S = LSHIFT(S,1);
	S = OR(S,ER[6+12]); S = LSHIFT(S,1);
	S = OR(S,ER[2+12]); S = LSHIFT(S,1);
	S = OR(S,ER[3+12]); S = LSHIFT(S,1);
	S = OR(S,ER[4+12]); S = LSHIFT(S,1);
	S = OR(S,ER[5+12]); S = S+1;
	S = SBOX3[S];

	FRK[9] = RSHIFT(AND(S,0x08),3);
	FRK[10] = RSHIFT(AND(S,0x04),2);
	FRK[11] = RSHIFT(AND(S,0x02),1);
	FRK[12] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+18]); S = LSHIFT(S,1);
	S = OR(S,ER[6+18]); S = LSHIFT(S,1);
	S = OR(S,ER[2+18]); S = LSHIFT(S,1);
	S = OR(S,ER[3+18]); S = LSHIFT(S,1);
	S = OR(S,ER[4+18]); S = LSHIFT(S,1);
	S = OR(S,ER[5+18]); S = S+1;
	S = SBOX4[S];

	FRK[13] = RSHIFT(AND(S,0x08),3);
	FRK[14] = RSHIFT(AND(S,0x04),2);
	FRK[15] = RSHIFT(AND(S,0x02),1);
	FRK[16] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+24]); S = LSHIFT(S,1);
	S = OR(S,ER[6+24]); S = LSHIFT(S,1);
	S = OR(S,ER[2+24]); S = LSHIFT(S,1);
	S = OR(S,ER[3+24]); S = LSHIFT(S,1);
	S = OR(S,ER[4+24]); S = LSHIFT(S,1);
	S = OR(S,ER[5+24]); S = S+1;
	S = SBOX5[S];

	FRK[17] = RSHIFT(AND(S,0x08),3);
	FRK[18] = RSHIFT(AND(S,0x04),2);
	FRK[19] = RSHIFT(AND(S,0x02),1);
	FRK[20] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+30]); S = LSHIFT(S,1);
	S = OR(S,ER[6+30]); S = LSHIFT(S,1);
	S = OR(S,ER[2+30]); S = LSHIFT(S,1);
	S = OR(S,ER[3+30]); S = LSHIFT(S,1);
	S = OR(S,ER[4+30]); S = LSHIFT(S,1);
	S = OR(S,ER[5+30]); S = S+1;
	S = SBOX6[S];

	FRK[21] = RSHIFT(AND(S,0x08),3);
	FRK[22] = RSHIFT(AND(S,0x04),2);
	FRK[23] = RSHIFT(AND(S,0x02),1);
	FRK[24] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+36]); S = LSHIFT(S,1);
	S = OR(S,ER[6+36]); S = LSHIFT(S,1);
	S = OR(S,ER[2+36]); S = LSHIFT(S,1);
	S = OR(S,ER[3+36]); S = LSHIFT(S,1);
	S = OR(S,ER[4+36]); S = LSHIFT(S,1);
	S = OR(S,ER[5+36]); S = S+1;
	S = SBOX7[S];

	FRK[25] = RSHIFT(AND(S,0x08),3);
	FRK[26] = RSHIFT(AND(S,0x04),2);
	FRK[27] = RSHIFT(AND(S,0x02),1);
	FRK[28] = AND(S,0x01);


	S = 0x00;
	S = OR(S,ER[1+42]); S = LSHIFT(S,1);
	S = OR(S,ER[6+42]); S = LSHIFT(S,1);
	S = OR(S,ER[2+42]); S = LSHIFT(S,1);
	S = OR(S,ER[3+42]); S = LSHIFT(S,1);
	S = OR(S,ER[4+42]); S = LSHIFT(S,1);
	S = OR(S,ER[5+42]); S = S+1;
	S = SBOX8[S];

	FRK[29] = RSHIFT(AND(S,0x08),3);
	FRK[30] = RSHIFT(AND(S,0x04),2);
	FRK[31] = RSHIFT(AND(S,0x02),1);
	FRK[32] = AND(S,0x01);

	FRK = permute(FRK,ROUND_P);

	return FRK;
end

local DES = {};

DES.blockSize = 8;

DES.encrypt = function(keyBlock,inputBlock)

	local LR = unpackBytes(inputBlock);
	local keyBits = unpackBytes(keyBlock);


	local CD = permute(keyBits,PC1);

	--key schedule
	CD = permute(CD,KS1); local KEY1 = permute(CD,PC2);
	CD = permute(CD,KS2); local KEY2 = permute(CD,PC2);
	CD = permute(CD,KS3); local KEY3 = permute(CD,PC2);
	CD = permute(CD,KS4); local KEY4 = permute(CD,PC2);
	CD = permute(CD,KS5); local KEY5 = permute(CD,PC2);
	CD = permute(CD,KS6); local KEY6 = permute(CD,PC2);
	CD = permute(CD,KS7); local KEY7 = permute(CD,PC2);
	CD = permute(CD,KS8); local KEY8 = permute(CD,PC2);
	CD = permute(CD,KS9); local KEY9 = permute(CD,PC2);
	CD = permute(CD,KS10); local KEY10 = permute(CD,PC2);
	CD = permute(CD,KS11); local KEY11 = permute(CD,PC2);
	CD = permute(CD,KS12); local KEY12 = permute(CD,PC2);
	CD = permute(CD,KS13); local KEY13 = permute(CD,PC2);
	CD = permute(CD,KS14); local KEY14 = permute(CD,PC2);
	CD = permute(CD,KS15); local KEY15 = permute(CD,PC2);
	CD = permute(CD,KS16); local KEY16 = permute(CD,PC2);

	--input permutation
	LR = permute(LR,IN_P);

	--rounds
	local frk = mix(LR,KEY1);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY2);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY3);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY4);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY5);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY6);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY7);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY8);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY9);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY10);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY11);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY12);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY13);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY14);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY15);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY16);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	--LR = permute(LR,LR_SWAP);

	--output permutation
	LR = permute(LR,OUT_P);

	local outputBlock = packBytes(LR);
	return outputBlock;
end

DES.decrypt = function(keyBlock,inputBlock)


	local LR = unpackBytes(inputBlock);
	local keyBits = unpackBytes(keyBlock);


	local CD = permute(keyBits,PC1);

	--key schedule
	CD = permute(CD,KS1); local KEY1 = permute(CD,PC2);
	CD = permute(CD,KS2); local KEY2 = permute(CD,PC2);
	CD = permute(CD,KS3); local KEY3 = permute(CD,PC2);
	CD = permute(CD,KS4); local KEY4 = permute(CD,PC2);
	CD = permute(CD,KS5); local KEY5 = permute(CD,PC2);
	CD = permute(CD,KS6); local KEY6 = permute(CD,PC2);
	CD = permute(CD,KS7); local KEY7 = permute(CD,PC2);
	CD = permute(CD,KS8); local KEY8 = permute(CD,PC2);
	CD = permute(CD,KS9); local KEY9 = permute(CD,PC2);
	CD = permute(CD,KS10); local KEY10 = permute(CD,PC2);
	CD = permute(CD,KS11); local KEY11 = permute(CD,PC2);
	CD = permute(CD,KS12); local KEY12 = permute(CD,PC2);
	CD = permute(CD,KS13); local KEY13 = permute(CD,PC2);
	CD = permute(CD,KS14); local KEY14 = permute(CD,PC2);
	CD = permute(CD,KS15); local KEY15 = permute(CD,PC2);
	CD = permute(CD,KS16); local KEY16 = permute(CD,PC2);

	--input permutation
	LR = permute(LR,IN_P);

	--rounds
	local frk = mix(LR,KEY16);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY15);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY14);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY13);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY12);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY11);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY10);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY9);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY8);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY7);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY6);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY5);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY4);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY3);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY2);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	LR = permute(LR,LR_SWAP);

	frk = mix(LR,KEY1);
	for k,v in pairs(frk) do LR[k] = XOR(LR[k],frk[k]); end
	--LR = permute(LR,LR_SWAP);

	--output permutation
	LR = permute(LR,OUT_P);

	local outputBlock = packBytes(LR);
	return outputBlock;
end

return DES;
