local PBKDF2 = require("lockbox.kdf.pbkdf2");
local HMAC = require("lockbox.mac.hmac");
local SHA1 = require("lockbox.digest.sha1");

local Bit = require("lockbox.util.bit");
local String = require("string");
local Stream = require("lockbox.util.stream");
local Array = require("lockbox.util.array");

local tests = {
	{
		pass = Array.fromString("password"),
		salt = Array.fromString("salt"),
		iter = 1,
		blockLen = 20,
		dKeyLen = 20,
		prf = HMAC().setBlockSize(64).setDigest(SHA1);
		output = "0c60c80f961f0e71f3a9b524af6012062fe037a6"
	},
	{
		pass = Array.fromString("password"),
		salt = Array.fromString("salt"),
		iter = 2,
		blockLen = 20,
		dKeyLen = 20,
		prf = HMAC().setBlockSize(64).setDigest(SHA1);
		output = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
	},
	{
		pass = Array.fromString("password"),
		salt = Array.fromString("salt"),
		iter = 4096,
		blockLen = 20,
		dKeyLen = 20,
		prf = HMAC().setBlockSize(64).setDigest(SHA1);
		output = "4b007901b765489abead49d926f721d065a429c1"
	},

};

for k,v in pairs(tests) do
	local res = PBKDF2()
			.setPRF(v.prf)
			.setBlockLen(v.blockLen)
			.setDKeyLen(v.dKeyLen)
			.setIterations(v.iter)
			.setSalt(v.salt)
			.setPassword(v.pass)
			.finish()
			.asHex();

	assert(String.lower(res) == v.output,
		String.format("TEST FAILED PASSWORD(%s) EXPECTED(%s) ACTUAL(%s)",
			Array.toString(v.pass),
			v.output,
			res));

end
