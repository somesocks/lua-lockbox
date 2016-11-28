local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.sha2_224");
local String = require("string");

local test = {};

test[""] = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
test["abc"] = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
test["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";
test["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end
