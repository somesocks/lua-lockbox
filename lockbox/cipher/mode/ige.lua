local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");
local Queue = require("lockbox.util.queue");

local String = require("string");
local Bit = require("lockbox.util.bit");

local IGE = {};

IGE.Cipher = function()

	local public = {};

	local key;
	local blockCipher;
	local padding;
	local inputQueue;
	local outputQueue;
	local xPrev,yPrev;

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
		xPrev = nil;
		yPrev = nil;
		return public;
	end

	public.update = function(messageStream)
		local byte = messageStream();
		while (byte ~= nil) do
			inputQueue.push(byte);
			if(inputQueue.size() >= blockCipher.blockSize) then
				local block = Array.readFromQueue(inputQueue,blockCipher.blockSize);

				if(yPrev == nil) then
					yPrev = block;
				elseif(xPrev == nil) then
					xPrev = block
				else
					local out = Array.XOR(yPrev,block);
					out = blockCipher.encrypt(key,out);
					out = Array.XOR(out,xPrev);
					Array.writeToQueue(outputQueue,out);
					xPrev = block;
					yPrev = out;
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

IGE.Decipher = function()

	local public = {};

	local key;
	local blockCipher;
	local padding;
	local inputQueue;
	local outputQueue;
	local xPrev,yPrev;

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
		xPrev = nil;
		yPrev = nil;
		return public;
	end

	public.update = function(messageStream)
		local byte = messageStream();
		while (byte ~= nil) do
			inputQueue.push(byte);
			if(inputQueue.size() >= blockCipher.blockSize) then
				local block = Array.readFromQueue(inputQueue,blockCipher.blockSize);

				if(xPrev == nil) then
					xPrev = block;
				elseif(yPrev == nil) then
					yPrev = block
				else
					local out = Array.XOR(yPrev,block);
					out = blockCipher.decrypt(key,out);
					out = Array.XOR(out,xPrev);
					Array.writeToQueue(outputQueue,out);
					xPrev = block;
					yPrev = out;
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

return IGE;

