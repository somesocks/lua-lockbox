local String = require("string");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local ECBMode = require("lockbox.cipher.mode.ecb");
local CBCMode = require("lockbox.cipher.mode.cbc");
local CFBMode = require("lockbox.cipher.mode.cfb");
local OFBMode = require("lockbox.cipher.mode.ofb");
local CTRMode = require("lockbox.cipher.mode.ctr");
local IGEMode = require("lockbox.cipher.mode.ige");

local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");

local AES128Cipher = require("lockbox.cipher.aes128");


local testVectors = {
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		iv = Array.fromHex(""),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("3ad77bb40d7a3660a89ecaf32466ef97"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		iv = Array.fromHex(""),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("f5d3d58503b9699de785895a96fdbaaf"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		iv = Array.fromHex(""),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("43b1cd7f598ece23881b00e3ed030688"),
		padding = ZeroPadding
	},
	{
		cipher = ECBMode.Cipher,
		decipher = ECBMode.Decipher,
		iv = Array.fromHex(""),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("7b0c785e27e8ad3f8223207104725dd4"),
		padding = ZeroPadding
	},


	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("7649abac8119b246cee98e9b12e9197d"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		iv = Array.fromHex("7649ABAC8119B246CEE98E9B12E9197D"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("5086cb9b507219ee95db113a917678b2"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		iv = Array.fromHex("5086CB9B507219EE95DB113A917678B2"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("73bed6b8e3c1743b7116e69e22229516"),
		padding = ZeroPadding
	},
	{
		cipher = CBCMode.Cipher,
		decipher = CBCMode.Decipher,
		iv = Array.fromHex("73BED6B8E3C1743B7116E69E22229516"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("3ff1caa1681fac09120eca307586e1a7"),
		padding = ZeroPadding
	},


	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		iv = Array.fromHex("000102030405060708090a0b0c0d0e0f"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("3b3fd92eb72dad20333449f8e83cfb4a"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		iv = Array.fromHex("3B3FD92EB72DAD20333449F8E83CFB4A"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("c8a64537a0b3a93fcde3cdad9f1ce58b"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		iv = Array.fromHex("C8A64537A0B3A93FCDE3CDAD9F1CE58B"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("26751f67a3cbb140b1808cf187a4f4df"),
		padding = ZeroPadding
	},
	{
		cipher = CFBMode.Cipher,
		decipher = CFBMode.Decipher,
		iv = Array.fromHex("26751F67A3CBB140B1808CF187A4F4DF"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("c04b05357c5d1c0eeac4c66f9ff7f2e6"),
		padding = ZeroPadding
	},

	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("6bc1bee22e409f96e93d7e117393172a"),
		ciphertext = Array.fromHex("3b3fd92eb72dad20333449f8e83cfb4a"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		iv = Array.fromHex("50FE67CC996D32B6DA0937E99BAFEC60"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
		ciphertext = Array.fromHex("7789508d16918f03f53c52dac54ed825"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		iv = Array.fromHex("D9A4DADA0892239F6B8B3D7680E15674"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
		ciphertext = Array.fromHex("9740051e9c5fecf64344f7a82260edcc"),
		padding = ZeroPadding
	},
	{
		cipher = OFBMode.Cipher,
		decipher = OFBMode.Decipher,
		iv = Array.fromHex("A78819583F0308E7A6BF36B1386ABF23"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex("304c6528f659c77866a510d9c1d6ae5e"),
		padding = ZeroPadding
	},

	{
		cipher = CTRMode.Cipher,
		decipher = CTRMode.Decipher,
		iv = Array.fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		plaintext = Array.fromHex(
			  "6bc1bee22e409f96e93d7e117393172a"
			.."ae2d8a571e03ac9c9eb76fac45af8e51"
			.."30c81c46a35ce411e5fbc1191a0a52ef"
			.."f69f2445df4f9b17ad2b417be66c3710"),
		ciphertext = Array.fromHex(
			  "874d6191b620e3261bef6864990db6ce"
			.."9806f66b7970fdff8617187bb9fffdff"
			.."5ae4df3edbd5d35e5b4f09020db03eab"
			.."1e031dda2fbe03d1792170a0f3009cee"),
		padding = ZeroPadding
	},
	{
		cipher = CTRMode.Cipher,
		decipher = CTRMode.Decipher,
		iv = Array.fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		key = Array.fromHex("2b7e151628aed2a6abf7158809cf4f3c"),
		ciphertext = Array.fromHex(
			  "874d6191b620e3261bef6864990db6ce"
			.."9806f66b7970fdff8617187bb9fffdff"
			.."5ae4df3edbd5d35e5b4f09020db03eab"
			.."1e031dda2fbe03d1792170a0f3009cee"),
		plaintext = Array.fromHex(
			  "6bc1bee22e409f96e93d7e117393172a"
			.."ae2d8a571e03ac9c9eb76fac45af8e51"
			.."30c81c46a35ce411e5fbc1191a0a52ef"
			.."f69f2445df4f9b17ad2b417be66c3710"),
		padding = ZeroPadding
	},

	{
		cipher = IGEMode.Cipher,
		decipher = IGEMode.Decipher,
		iv = Array.fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
		key = Array.fromHex("000102030405060708090A0B0C0D0E0F"),
		plaintext = Array.fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
		ciphertext = Array.fromHex("1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB"),
		padding = ZeroPadding
	},

	{
		cipher = IGEMode.Cipher,
		decipher = IGEMode.Decipher,
		iv = Array.fromHex("6D656E746174696F6E206F6620494745206D6F646520666F72204F70656E5353"),
		key = Array.fromHex("5468697320697320616E20696D706C65"),
		plaintext = Array.fromHex("99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B"),
		ciphertext = Array.fromHex("4C2E204C6574277320686F70652042656E20676F74206974207269676874210A"),
		padding = ZeroPadding
	},


};

for k,v in pairs(testVectors) do
	local cipher = v.cipher()
			.setKey(v.key)
			.setBlockCipher(AES128Cipher)
			.setPadding(v.padding);

	local cipherOutput = cipher
						.init()
						.update(Stream.fromArray(v.iv))
						.update(Stream.fromArray(v.plaintext))
						.finish()
						.asHex();

	local decipher = v.decipher()
			.setKey(v.key)
			.setBlockCipher(AES128Cipher)
			.setPadding(v.padding);

	local plainOutput = decipher
						.init()
						.update(Stream.fromArray(v.iv))
						.update(Stream.fromArray(v.ciphertext))
						.finish()
						.asHex();

	assert(cipherOutput == Array.toHex(v.ciphertext)
				,String.format("cipher failed!  expected(%s) got(%s)",Array.toHex(v.ciphertext),cipherOutput));

	assert(plainOutput == Array.toHex(v.plaintext)
				,String.format("decipher failed!  expected(%s) got(%s)",Array.toHex(v.plaintext),plainOutput));

end
