local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.sha1");
local String = require("string");

local test = {};

test[""] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
test["abc"] = "a9993e364706816aba3e25717850c26c9cd0d89d";
test["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
test["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = "a49b2446a02c645bf419f995b67091253a04a259";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end
