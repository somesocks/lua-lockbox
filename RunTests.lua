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
	"HKDFTests",
	"PBKDF2Tests",
	"DESCipherTests",
	"DES3CipherTests",
	"AES128CipherTests",
	"AES192CipherTests",
	"AES256CipherTests",
	"TEACipherTests",
	"XTEACipherTests",
	};

local status = 0

for k,v in pairs(tests) do
	print(String.format("Running %s...",v));
	local ok, err = pcall(
	function()
		require("test."..v)
	end
	);
	if not ok then
		print(String.format("FAIL: %s failed with error:\n%s\n", v, err));
		status = 1
	else
		print(String.format("%s passed!\n",v));
	end
end

os.exit(status)
