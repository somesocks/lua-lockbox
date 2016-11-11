local String = require("string");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local ECBMode = require("lockbox.cipher.mode.ecb");
local CBCMode = require("lockbox.cipher.mode.cbc");
local CFBMode = require("lockbox.cipher.mode.cfb");
local OFBMode = require("lockbox.cipher.mode.ofb");
local CTRMode = require("lockbox.cipher.mode.ctr");

local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");

local AES256Cipher = require("lockbox.cipher.aes256");


local testVectors = {
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("f3eed1bdb5d2a03c064b5a7e3db181f8"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("591ccb10d410ed26dc5ba74a31362870"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("b6ed21b99ca6f4f9f153e7b1beafed1d"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("23304b7a39f9f3ff067d8d8f9e24ecc7"),
		padding = ZeroPadding
	},


	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("9cfc4e967edb808d679f777bc6702c7d"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("9CFC4E967EDB808D679F777BC6702C7D"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("39f23369a9d9bacfa530e26304231461"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("39F23369A9D9BACFA530E26304231461"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("b2eb05e2c39be9fcda6c19078c6a9d1b"),
		padding = ZeroPadding
	},


	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("DC7E84BFDA79164B7ECD8486985D3860"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("DC7E84BFDA79164B7ECD8486985D3860"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("39ffed143b28b1c832113c6331e5407b"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("39FFED143B28B1C832113C6331E5407B"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("df10132415e54b92a13ed0a8267ae2f9"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("DF10132415E54B92A13ED0A8267AE2F9"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("75a385741ab9cef82031623d55b1e471"),
		padding = ZeroPadding
	},


	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("dc7e84bfda79164b7ecd8486985d3860"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("B7BF3A5DF43989DD97F0FA97EBCE2F4A"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("4febdc6740d20b3ac88f6ad82a4fb08d"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("E1C656305ED1A7A6563805746FE03EDC"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("71ab47a086e86eedf39d1c5bba97c408"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("41635BE625B48AFC1666DD42A09D96E7"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("0126141d67f37be8538f5a8be740e484"),
		padding = ZeroPadding
	},

	{
		cipher = CTRMode.Cipher,
		decipher = CTRMode.Decipher,
		key = Array.fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
		iv = Array.fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"),
		padding = ZeroPadding
	},


};

for k,v in pairs(testVectors) do
	local cipher = v.cipher()
			.setKey(v.key)
			.setBlockCipher(AES256Cipher)
			.setPadding(v.padding);

	local cipherOutput = cipher
						.init()
						.update(Stream.fromArray(v.iv))
						.update(Stream.fromArray(v.plaintext))
						.finish()
						.asHex();

	local decipher = v.decipher()
			.setKey(v.key)
			.setBlockCipher(AES256Cipher)
			.setPadding(v.padding);

	local plainOutput = decipher
						.init()
						.update(Stream.fromArray(v.iv))
						.update(Stream.fromHex(cipherOutput))
						.finish()
						.asHex();

	assert(cipherOutput == Array.toHex(v.ciphertext)
				,String.format("cipher failed!  expected(%s) got(%s)",Array.toHex(v.ciphertext),cipherOutput));

	assert(plainOutput == Array.toHex(v.plaintext)
				,String.format("decipher failed!  expected(%s) got(%s)",Array.toHex(v.plaintext),plainOutput));

end
