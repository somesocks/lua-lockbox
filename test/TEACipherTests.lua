local String = require("string");

local Array = require("Array");
local Stream = require("Stream");

local ECBMode = require("ECBMode");

local CBCMode = require("CBCMode");

local PKCS7Padding = require("PKCS7Padding");
local ZeroPadding = require("ZeroPadding");

local TEACipher = require("TEACipher");

local testVectors = {

	{
		mode = ECBMode,
		key = Array.fromHex("00000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("41ea3a0a94baa940"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("00000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0102030405060708"),
		ciphertext = Array.fromHex("6a2f9cf3fccf3c55"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0123456712345678234567893456789a"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("34e943b0900f5dcb"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0123456712345678234567893456789a"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0102030405060708"),
		ciphertext = Array.fromHex("773dc179878a81c0"),
		padding = ZeroPadding
	},

};

for k,v in pairs(testVectors) do

	local cipher = v.mode.Cipher()
			.setKey(v.key)
			.setBlockCipher(TEACipher)
			.setPadding(v.padding);

	local res = cipher
				.init()
				.update(Stream.fromArray(v.iv))
				.update(Stream.fromArray(v.plaintext))
				.finish()
				.asHex();

	assert(res == Array.toHex(v.ciphertext),
			String.format("test failed! TEA encrypt expected(%s) got(%s)",Array.toHex(v.ciphertext),res));

	local decipher = v.mode.Decipher()
			.setKey(v.key)
			.setBlockCipher(TEACipher)
			.setPadding(v.padding);

	local res2 = decipher
				.init()
				.update(Stream.fromArray(v.iv))
				.update(Stream.fromArray(v.ciphertext))
				.finish()
				.asHex();
	
	assert(res2 == Array.toHex(v.plaintext),
			String.format("test failed! TEA decrypt expected(%s) got(%s)",Array.toHex(v.plaintext),res2));

end
