local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");
local Queue = require("lockbox.util.queue");

local String = require("string");
local Bit = require("lockbox.util.bit");

local AND = Bit.band;
local OR  = Bit.bor;
local NOT = Bit.bnot;
local XOR = Bit.bxor;
local LROT = Bit.lrotate;
local RROT = Bit.rrotate;
local LSHIFT = Bit.lshift;
local RSHIFT = Bit.rshift;

--CTR counter is big-endian
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


local CTR = {};

CTR.Cipher = function()

	local public = {};

	local key;
	local blockCipher;
	local padding;
	local inputQueue;
	local outputQueue;
	local iv;

	public.setKey = function(keyBytes)
		key = keyBytes;
		return public;
	end

	public.setBlockCipher = function(cipher)
		blockCipher = cipher;
		return public;
	end

	public.setPadding = function(paddingMode)
		padding = paddingMode;
		return public;
	end

	public.init = function()
		inputQueue = Queue();
		outputQueue = Queue();
		iv = nil;
		return public;
	end

	local updateIV = function()
		iv[16] = iv[16] + 1;
		if iv[16] <= 0xFF then return; end
		iv[16] = AND(iv[16],0xFF);

		iv[15] = iv[15] + 1;
		if iv[15] <= 0xFF then return; end
		iv[15] = AND(iv[15],0xFF);

		iv[14] = iv[14] + 1;
		if iv[14] <= 0xFF then return; end
		iv[14] = AND(iv[14],0xFF);

		iv[13] = iv[13] + 1;
		if iv[13] <= 0xFF then return; end
		iv[13] = AND(iv[13],0xFF);

		iv[12] = iv[12] + 1;
		if iv[12] <= 0xFF then return; end
		iv[12] = AND(iv[12],0xFF);

		iv[11] = iv[11] + 1;
		if iv[11] <= 0xFF then return; end
		iv[11] = AND(iv[11],0xFF);

		iv[10] = iv[10] + 1;
		if iv[10] <= 0xFF then return; end
		iv[10] = AND(iv[10],0xFF);

		iv[9] = iv[9] + 1;
		if iv[9] <= 0xFF then return; end
		iv[9] = AND(iv[9],0xFF);

		return;
	end

	public.update = function(messageStream)
		local byte = messageStream();
		while (byte ~= nil) do
			inputQueue.push(byte);

			if(inputQueue.size() >= blockCipher.blockSize) then
				local block = Array.readFromQueue(inputQueue,blockCipher.blockSize);

				if(iv == nil) then
					iv = block;
				else
					local out = iv;
					out = blockCipher.encrypt(key,out);

					out = Array.XOR(out,block);
					Array.writeToQueue(outputQueue,out);
					updateIV();
				end
			end
			byte = messageStream();
		end
		return public;
	end

	public.finish = function()
		paddingStream = padding(blockCipher.blockSize,inputQueue.getHead());
		public.update(paddingStream);

		return public;
	end

	public.getOutputQueue = function()
		return outputQueue;
	end

	public.asHex = function()
		return Stream.toHex(outputQueue.pop);
	end

	public.asBytes = function()
		return Stream.toArray(outputQueue.pop);
	end

	return public;

end


CTR.Decipher = function()

	local public = {};

	local key;
	local blockCipher;
	local padding;
	local inputQueue;
	local outputQueue;
	local iv;

	public.setKey = function(keyBytes)
		key = keyBytes;
		return public;
	end

	public.setBlockCipher = function(cipher)
		blockCipher = cipher;
		return public;
	end

	public.setPadding = function(paddingMode)
		padding = paddingMode;
		return public;
	end

	public.init = function()
		inputQueue = Queue();
		outputQueue = Queue();
		iv = nil;
		return public;
	end

	local updateIV = function()
		iv[16] = iv[16] + 1;
		if iv[16] <= 0xFF then return; end
		iv[16] = AND(iv[16],0xFF);

		iv[15] = iv[15] + 1;
		if iv[15] <= 0xFF then return; end
		iv[15] = AND(iv[15],0xFF);

		iv[14] = iv[14] + 1;
		if iv[14] <= 0xFF then return; end
		iv[14] = AND(iv[14],0xFF);

		iv[13] = iv[13] + 1;
		if iv[13] <= 0xFF then return; end
		iv[13] = AND(iv[13],0xFF);

		iv[12] = iv[12] + 1;
		if iv[12] <= 0xFF then return; end
		iv[12] = AND(iv[12],0xFF);

		iv[11] = iv[11] + 1;
		if iv[11] <= 0xFF then return; end
		iv[11] = AND(iv[11],0xFF);

		iv[10] = iv[10] + 1;
		if iv[10] <= 0xFF then return; end
		iv[10] = AND(iv[10],0xFF);

		iv[9] = iv[9] + 1;
		if iv[9] <= 0xFF then return; end
		iv[9] = AND(iv[9],0xFF);

		return;
	end

	public.update = function(messageStream)
		local byte = messageStream();
		while (byte ~= nil) do
			inputQueue.push(byte);

			if(inputQueue.size() >= blockCipher.blockSize) then
				local block = Array.readFromQueue(inputQueue,blockCipher.blockSize);

				if(iv == nil) then
					iv = block;
				else
					local out = iv;
					out = blockCipher.encrypt(key,out);

					out = Array.XOR(out,block);
					Array.writeToQueue(outputQueue,out);
					updateIV();
				end
			end
			byte = messageStream();
		end
		return public;
	end

	public.finish = function()
		paddingStream = padding(blockCipher.blockSize,inputQueue.getHead());
		public.update(paddingStream);

		return public;
	end

	public.getOutputQueue = function()
		return outputQueue;
	end

	public.asHex = function()
		return Stream.toHex(outputQueue.pop);
	end

	public.asBytes = function()
		return Stream.toArray(outputQueue.pop);
	end

	return public;

end




return CTR;

