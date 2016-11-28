local String = require("string");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local ECBMode = require("lockbox.cipher.mode.ecb");

local CBCMode = require("lockbox.cipher.mode.cbc");

local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");

local DES3Cipher = require("lockbox.cipher.des3");

local testVectors = {
	{
		mode = ECBMode,
		key = Array.fromHex("8000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext= Array.fromHex("95A8D72813DAA94D"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("4000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("0EEC1487DD8C26D5"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("2000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("7AD16FFB79C45926"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("1000000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("D3746294CA6A6CF3"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0800000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("809F5F873C1FD761"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0400000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("C02FAFFEC989D1FC"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0200000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("4615AA1D33E72F10"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key = Array.fromHex("0100000000000000"),
		iv = Array.fromString(""),
		plaintext = Array.fromHex("0000000000000000"),
		ciphertext = Array.fromHex("8CA64DE9C1B123A7"),
		padding = ZeroPadding
	},

	{
		mode = CBCMode,
		key = Array.fromString("12345678"),
		iv = Array.fromString("abcdefgh"),
		plaintext = Array.fromString("This is the message to encrypt!!"),
		ciphertext = Array.fromHex("6CA9470C849D1CC1A59FFC148F1CB5E9CF1F5C0328A7E8756387FF4D0FE46050"),
		padding = PKCS7Padding
	},


	{
		mode = ECBMode,
		key=Array.fromHex("80000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("FAFD5084374FCE34"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("40000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("60CC37B7B537A1DC"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("20000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("BE3E7304FE92C2BC"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("10000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("49F9E7A60C406DBF"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("08000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("794FE1DC2F80CD38"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("04000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("15052BCDF21A1F1E"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("02000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("3A830D0BDA044EBB"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("01000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("8CA64DE9C1B123A7"),
		padding = ZeroPadding
	},


	{
		mode = ECBMode,
		key=Array.fromHex("800000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("95A8D72813DAA94D"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("400000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("0EEC1487DD8C26D5"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("200000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("7AD16FFB79C45926"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("100000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("D3746294CA6A6CF3"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("080000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("809F5F873C1FD761"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("040000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("C02FAFFEC989D1FC"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("020000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("4615AA1D33E72F10"),
		padding = ZeroPadding
	},
	{
		mode = ECBMode,
		key=Array.fromHex("010000000000000000000000000000000000000000000000"),
		iv = Array.fromString(""),
		plaintext=Array.fromHex("0000000000000000"),
		ciphertext=Array.fromHex("8CA64DE9C1B123A7"),
		padding = ZeroPadding
	}


};

for k,v in pairs(testVectors) do

	local cipher = v.mode.Cipher()
			.setKey(v.key)
			.setBlockCipher(DES3Cipher)
			.setPadding(v.padding);

	local res = cipher
				.init()
				.update(Stream.fromArray(v.iv))
				.update(Stream.fromArray(v.plaintext))
				.finish()
				.asHex();

	assert(res == Array.toHex(v.ciphertext),
			String.format("test failed! DES encrypt expected(%s) got(%s)",Array.toHex(v.ciphertext),res));

	local decipher = v.mode.Decipher()
			.setKey(v.key)
			.setBlockCipher(DES3Cipher)
			.setPadding(v.padding);

	local res = decipher
				.init()
				.update(Stream.fromArray(v.iv))
				.update(Stream.fromArray(v.ciphertext))
				.finish()
				.asBytes();

	assert(Array.toHex(res) == Array.toHex(v.plaintext),
			String.format("test failed! DES decrypt expected(%s) got(%s)",Array.toString(v.plaintext),Array.toString(res)));

end
