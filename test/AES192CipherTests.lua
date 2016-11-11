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

local AES192Cipher = require("lockbox.cipher.aes192");


local testVectors = {
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("bd334f1d6e45f25ff712a214571fa5cc"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("974104846d0ad3ad7734ecb3ecee4eef"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("ef7afd2270e2e60adce0ba2face6444e"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex(""),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("9a4b41ba738d6c72fb16691603c18e0e"),
		padding = ZeroPadding
	},


	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("4f021db243bc633d7178183a9fa071e8"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("4F021DB243BC633D7178183A9FA071E8"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("b4d9ada9ad7dedf4e5e738763f69145a"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("B4D9ADA9AD7DEDF4E5E738763F69145A"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("571b242012fb7ae07fa9baac3df102e0"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("571B242012FB7AE07FA9BAAC3DF102E0"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("08b0e27988598881d920a9e64f5615cd"),
		padding = ZeroPadding
	},


	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("cdc80d6fddf18cab34c25909c99a4174"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("CDC80D6FDDF18CAB34C25909C99A4174"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("67ce7f7f81173621961a2b70171d3d7a"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("67CE7F7F81173621961A2B70171D3D7A"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("2e1e8a1dd59b88b1c8e60fed1efac4c9"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("2E1E8A1DD59B88B1C8E60FED1EFAC4C9"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("c05f9f9ca9834fa042ae8fba584b09ff"),
		padding = ZeroPadding
	},


	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("cdc80d6fddf18cab34c25909c99a4174"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("A609B38DF3B1133DDDFF2718BA09565E"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("fcc28b8d4c63837c09e81700c1100401"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("52EF01DA52602FE0975F78AC84BF8A50"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("8d9a9aeac0f6596f559c6d4daf59a5f2"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("BD5286AC63AABD7EB067AC54B553F71D"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("6d9f200857ca6c3e9cac524bd9acc92a"),
		padding = ZeroPadding
	},

	{
		cipher = CTRMode.Cipher,
		decipher = CTRMode.Decipher,
		key = Array.fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		iv = Array.fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"),
		padding = ZeroPadding
	},


};

for k,v in pairs(testVectors) do
	local cipher = v.cipher()
			.setKey(v.key)
			.setBlockCipher(AES192Cipher)
			.setPadding(v.padding);

	local cipherOutput = cipher
						.init()
						.update(Stream.fromArray(v.iv))
						.update(Stream.fromArray(v.plaintext))
						.finish()
						.asHex();

	local decipher = v.decipher()
			.setKey(v.key)
			.setBlockCipher(AES192Cipher)
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
