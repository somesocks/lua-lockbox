local String = require("string");
local Lockbox = require("Lockbox");

Lockbox.ALLOW_INSECURE = true;

local tests = {
	"MD2Tests",
	"MD4Tests",
	"MD5Tests",
	"RIPEMD128Tests",
	"RIPEMD160Tests",
	"SHA1Tests",
	"SHA2_224Tests",
	"SHA2_256Tests",
	"HMACTests",
	"PBKDF2Tests",
	"DESCipherTests",
	"AES128CipherTests",
	"AES192CipherTests",
	};

for k,v in pairs(tests) do
	print(String.format("Running %s...",v));
	require(v);
	print(String.format("%s passed!\n",v));
end

