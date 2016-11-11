local Stream = require("lockbox.util.stream");
local Digest = require("lockbox.digest.md5");
local String = require("string");

local test = {};

test["The quick brown fox jumps over the lazy dog"] = "9e107d9d372bb6826bd81d3542a419d6";
test["The quick brown fox jumps over the lazy dog."] = "e4d909c290d0fb1ca068ffaddf22cbd0";
test[""]    = "d41d8cd98f00b204e9800998ecf8427e";
test["abc"] = "900150983cd24fb0d6963f7d28e17f72";

for k,v in pairs(test) do
	local message = k;
	local expected = v;
	local actual = Digest()
					.update(Stream.fromString(k))
					.finish()
					.asHex();

	assert(actual == expected, String.format("Test failed! MESSAGE(%s) Expected(%s) Actual(%s)",message,expected,actual));

end


