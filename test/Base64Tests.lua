local String = require("string");
local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");
local Base64 = require("lockbox.util.base64");

local test_vectors = {
	{
		plain = "foobar",
		enc = "Zm9vYmFy"
	},
	{
		plain = "fooba",
		enc = "Zm9vYmE="
	},
	{
		plain = "foob",
		enc = "Zm9vYg=="
	},
	{
		plain = "foo",
		enc = "Zm9v"
	},
	{
		plain = "fo",
		enc = "Zm8="
	},
	{
		plain = "f",
		enc = "Zg=="
	},
	{
		plain = "",
		enc = ""
	},


};

for k,v in pairs(test_vectors) do
	local out = Base64.fromStream(Stream.fromString(v.plain));
	assert(out == v.enc,String.format("STREAM ENCODING FAILED expected(%s) actual(%s)",v.enc,out));

	local out = Base64.fromString(v.plain);
	assert(out == v.enc,String.format("ARRAY ENECODING FAILED expected(%s) actual(%s)",v.enc,out));

	local out = Base64.toArray(v.enc);
	out = Array.toString(out);

	assert(out == v.plain,String.format("ARRAY DECODING FAILED expected(%s) actual(%s)",v.plain,out));

	local out = Base64.toString(v.enc);
	assert(out == v.plain,String.format("ARRAY DECODING FAILED expected(%s) actual(%s)",v.plain,out));

end
