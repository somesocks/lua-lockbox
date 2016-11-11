local String = require("string");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local ECBMode = require("lockbox.cipher.mode.ecb");
local CBCMode = require("lockbox.cipher.mode.cbc");

local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");

local XTEACipher = require("lockbox.cipher.xtea");

local testVectors = {

	{
		mode = ECBMode,
		key = Array.fromHex("27F917B1C1DA899360E2ACAAA6EB923D"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("AF20A390547571AA"),
		ciphertext = Array.fromHex("D26428AF0A202283"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("31415926535897932384626433832795"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0288419716939937"),
		ciphertext = Array.fromHex("46E2007D58BBC2EA"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("1234ABC1234ABC1234ABC1234ABC1234"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("ABC1234ABC1234AB"),
		ciphertext = Array.fromHex("5C0754C1F6F0BD9B"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("ABC1234ABC1234ABC1234ABC1234ABC1"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("234ABC1234ABC123"),
		ciphertext = Array.fromHex("CDFCC72C24BC116B"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("DEADBEEFDEADBEEF"),
		ciphertext = Array.fromHex("FAF28CB50940C0E0"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("9647A9189EC565D5"),
		ciphertext = Array.fromHex("DEADBEEFDEADBEEF"),
		padding = ZeroPadding
	},
};

for k,v in pairs(testVectors) do

	local cipher = v.mode.Cipher()
			.setKey(v.key)
			.setBlockCipher(XTEACipher)
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
			.setBlockCipher(XTEACipher)
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
