local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.md2");
local String = require("string");

local test = {};
test[""] = "8350e5a3e24c153df2275c9f80692773";
test["a"] = "32ec01ec4a6dac72c0ab96fb34c0b5d1";
test["abc"] = "da853b0d3f88d99b30283a69e6ded6bb";
test["message digest"] = "ab4f496bfb2a530b219ff33031fe06b0";
test["abcdefghijklmnopqrstuvwxyz"] = "4e8ddff3650292ab5a4108c3aa47940b";
test["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"] = "da33def2a42df13975352846c30338cd";
test["12345678901234567890123456789012345678901234567890123456789012345678901234567890"] = "d5976f79d83d3a0dc9806c3c66f3efd8";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end
