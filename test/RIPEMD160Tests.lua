local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.ripemd160");
local String = require("string");

local test = {};

test[""]  = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
test["a"] = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe";
test["abc"] = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
test["message digest"] = "5d0689ef49d2fae572b881b123a85ffa21595f36";
test["abcdefghijklmnopqrstuvwxyz"] = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc";
test["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = "12a053384a9c0c88e405a06c27dcf49ada62eb2b";
test["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"] = "b0e20b6e3116640286ed3a87a5713079b21f5189";
test["12345678901234567890123456789012345678901234567890123456789012345678901234567890"] = "9b752e45573d4b39f4dbd3323cab82bf63326bfb";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end

