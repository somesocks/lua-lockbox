local String = require("string");

local Array = require("Array");
local Stream = require("Stream");

local ECBMode = require("ECBMode");

local CBCMode = require("CBCMode");

local PCKS7Padding = require("PCKS7Padding");
local ZeroPadding = require("ZeroPadding");

local DESCipher = require("DESCipher");

local testVectors = {
	{
		cipher = ECBMode.Cipher,
		key = {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "95A8D72813DAA94D",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "0EEC1487DD8C26D5",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "7AD16FFB79C45926",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "D3746294CA6A6CF3",
		padding = ZeroPadding
	},




	{
		cipher = ECBMode.Cipher,
		key = {0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "809F5F873C1FD761",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "C02FAFFEC989D1FC",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "4615AA1D33E72F10",
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		key = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		plaintext = Stream.fromHex("0000000000000000"),
		ciphertext = "8CA64DE9C1B123A7",
		padding = ZeroPadding
	},

	{
		cipher = CBCMode.Cipher,
		key = Array.fromString("12345678"),
		plaintext = Stream.fromString("abcdefghThis is the message to encrypt!!"),
		ciphertext = String.upper("6ca9470c849d1cc1a59ffc148f1cb5e9cf1f5c0328a7e8756387ff4d0fe46050"),
		padding = PCKS7Padding
	},

};

for k,v in pairs(testVectors) do

	local cipher = v.cipher()
			.setKey(v.key)
			.setBlockCipher(DESCipher)
			.setPadding(v.padding);

	local res = cipher
				.init()
				.update(v.plaintext)
				.finish()
				.asHex();

	assert(res == v.ciphertext,String.format("test failed! expected(%s) got(%s)",v.ciphertext,res));

end
