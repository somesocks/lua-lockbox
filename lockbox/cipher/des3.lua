require("lockbox").insecure();

local Array = require("lockbox.util.array");

local DES = require("lockbox.cipher.des");

local DES3 = {};

local getKeys = function(keyBlock)
	local size = Array.size(keyBlock)

	local key1;
	local key2;
	local key3;

	if (size == 8) then
		key1 = keyBlock;
		key2 = keyBlock;
		key3 = keyBlock;
	elseif (size == 16) then
		key1 = Array.slice(keyBlock,1,8);
		key2 = Array.slice(keyBlock,9,16);
		key3 = key1;
	elseif (size == 24) then
		key1 = Array.slice(keyBlock,1,8);
		key2 = Array.slice(keyBlock,9,16);
		key3 = Array.slice(keyBlock,17,24);
	else
		assert(false,"Invalid key size for 3DES");
	end

	return key1,key2,key3;
end

DES3.blockSize = DES.blockSize;

DES3.encrypt = function(keyBlock,inputBlock)
	local key1;
	local key2;
	local key3;

	key1, key2, key3 = getKeys(keyBlock);

	local block = inputBlock;
	block = DES.encrypt(key1,block);
	block = DES.decrypt(key2,block);
	block = DES.encrypt(key3,block);

	return block;
end

DES3.decrypt = function(keyBlock,inputBlock)
	local key1;
	local key2;
	local key3;

	key1, key2, key3 = getKeys(keyBlock);

	local block = inputBlock;
	block = DES.decrypt(key3,block);
	block = DES.encrypt(key2,block);
	block = DES.decrypt(key1,block);

	return block;
end

return DES3;
