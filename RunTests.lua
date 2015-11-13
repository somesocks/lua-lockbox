local String = require("string");
local Lockbox = require("lockbox");

Lockbox.ALLOW_INSECURE = true;

local tests = {
	"Base64Tests",
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
	"DES3CipherTests",
	"AES128CipherTests",
	"AES192CipherTests",
	"AES256CipherTests",
	"TEACipherTests",
	"XTEACipherTests",
	};

for k,v in pairs(tests) do
	print(String.format("Running %s...",v));
	require("test."..v);
	print(String.format("%s passed!\n",v));
end

