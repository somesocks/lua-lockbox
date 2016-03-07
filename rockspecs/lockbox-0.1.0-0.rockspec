package = "lockbox"
version = "0.1.0-0"
source = {
	url = "git://github.com/somesocks/lua-lockbox.git",
	tag = "0.1.0"
}
description = {
	summary = "A collection of cryptographic primitives written in pure Lua",
	detailed = [[
A collection of cryptographic primitives and protocols written in pure Lua. This was written to provide cross-platform, tested reference implementations of many different cryptographic primitives.
	]],
	homepage = "https://github.com/somesocks/lua-lockbox",
	maintainer = "James L.",
	license = "MIT/X11"
}
dependencies = {
	"lua >= 5.2"
}
build = {
	type = 'builtin',
	modules = {
		['lockbox'] = 'lockbox/init.lua',
		['lockbox.digest.sha2_224'] = 'lockbox/digest/sha2_224.lua',
		['lockbox.digest.md4'] = 'lockbox/digest/md4.lua',
		['lockbox.digest.ripemd160'] = 'lockbox/digest/ripemd160.lua',
		['lockbox.digest.ripemd128'] = 'lockbox/digest/ripemd128.lua',
		['lockbox.digest.md5'] = 'lockbox/digest/md5.lua',
		['lockbox.digest.md2'] = 'lockbox/digest/md2.lua',
		['lockbox.digest.sha1'] = 'lockbox/digest/sha1.lua',
		['lockbox.digest.sha2_256'] = 'lockbox/digest/sha2_256.lua',
		['lockbox.mac.hmac'] = 'lockbox/mac/hmac.lua',
		['lockbox.padding.isoiec7816'] = 'lockbox/padding/isoiec7816.lua',
		['lockbox.padding.pkcs7'] = 'lockbox/padding/pkcs7.lua',
		['lockbox.padding.zero'] = 'lockbox/padding/zero.lua',
		['lockbox.padding.ansix923'] = 'lockbox/padding/ansix923.lua',
		['lockbox.kdf.pbkdf2'] = 'lockbox/kdf/pbkdf2.lua',
		['lockbox.util.base64'] = 'lockbox/util/base64.lua',
		['lockbox.util.array'] = 'lockbox/util/array.lua',
		['lockbox.util.queue'] = 'lockbox/util/queue.lua',
		['lockbox.util.bit'] = 'lockbox/util/bit.lua',
		['lockbox.util.stream'] = 'lockbox/util/stream.lua',
		['lockbox.cipher.mode.pcbc'] = 'lockbox/cipher/mode/pcbc.lua',
		['lockbox.cipher.mode.ctr'] = 'lockbox/cipher/mode/ctr.lua',
		['lockbox.cipher.mode.cbc'] = 'lockbox/cipher/mode/cbc.lua',
		['lockbox.cipher.mode.cfb'] = 'lockbox/cipher/mode/cfb.lua',
		['lockbox.cipher.mode.ofb'] = 'lockbox/cipher/mode/ofb.lua',
		['lockbox.cipher.mode.ecb'] = 'lockbox/cipher/mode/ecb.lua',
		['lockbox.cipher.mode.ige'] = 'lockbox/cipher/mode/ige.lua',
		['lockbox.cipher.des'] = 'lockbox/cipher/des.lua',
		['lockbox.cipher.aes192'] = 'lockbox/cipher/aes192.lua',
		['lockbox.cipher.aes128'] = 'lockbox/cipher/aes128.lua',
		['lockbox.cipher.des3'] = 'lockbox/cipher/des3.lua',
		['lockbox.cipher.aes256'] = 'lockbox/cipher/aes256.lua'
	}
}

