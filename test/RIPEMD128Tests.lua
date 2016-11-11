local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.ripemd128");
local String = require("string");

local test = {};

test[""]  = "cdf26213a150dc3ecb610f18f6b38b46";
test["a"] = "86be7afa339d0fc7cfc785e72f578d33";
test["abc"] = "c14a12199c66e4ba84636b0f69144c77";
test["message digest"] = "9e327b3d6e523062afc1132d7df9d1b8";
test["abcdefghijklmnopqrstuvwxyz"] = "fd2aa607f71dc8f510714922b371834e";
test["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = "a1aa0689d0fafa2ddc22e88b49133a06";
test["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"] = "d1e959eb179c911faea4624c60c5c702";
test["12345678901234567890123456789012345678901234567890123456789012345678901234567890"] = "3f45ef194732c2dbb2c4a2c769795fa3";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end
