--[[
  Lockbox - crude performance tests

  Based off of test_perf.lua from https://github.com/philanc/plc
  Modified to work with Lockbox's API.
]]


local Lockbox = require("lockbox")
Lockbox.ALLOW_INSECURE = true
------------------------------------------------------------

local Stream = require("lockbox.util.stream")
local Array = require("lockbox.util.array")

------------------------------------------------------------

local function pf(...) print(string.format(...)) end

local start, done do
  local c0, desc, cmt
  start = function (d, c)
      desc = d
      cmt = c and "-- " .. c or "" --optional comment
      c0 = os.clock()
  end
  done = function ()
      local dc = os.clock() - c0
      pf("- %-30s %7.1f  %s", desc, dc, cmt)
  end
end


local sizemb = 1  -- plain text size (in MBytes)
local mega = 1024 * 1024
local size = mega * sizemb
local plain = ('a'):rep(size)
local k8  = ('k'):rep(8)
local k16 = k8:rep(2)
local k32 = k16:rep(2)
local iv8 = ('i'):rep(8)
local iv16 = iv8:rep(2)
local iv32 = iv16:rep(2)

------------------------------------------------------------

local function perf_digest(dig)
    local algo = require ("lockbox.digest." .. dig)
    local m = plain

    start(dig)
    algo().update( Stream.fromString(m) ).finish()
    done()
end

------------------------------------------------------------

local function perf_hmacdigest(dig)
    local hmac = require ("lockbox.mac.hmac")
    local algo = require ("lockbox.digest." .. dig)

    local key = Array.fromString(k16)

    local m = plain

    start("hmac_" .. dig)
    hmac = hmac().setBlockSize(64).setDigest(algo).setKey(key)
    hmac.update( Stream.fromString(m) ).finish()
    done()
end

------------------------------------------------------------

local function perf_blockcipher(algo, mode, padding, params)
    local desc = string.format("%s_%s + %sPad", algo, mode, padding)
    mode = require ("lockbox.cipher.mode." .. mode)
    algo = require ("lockbox.cipher." .. algo)
    padding = require ("lockbox.padding." .. padding)

    params = params or {}
    params.key = params.key or k16
    params.iv = params.iv or iv16

    local key = Array.fromString(params.key)
    local iv  = Array.fromString(params.iv)

    local m = not params.downscale
              and plain
              or plain:sub(1, math.min(size, size * params.downscale))
    local ciphertext

    start(desc .. " encrypt", #m ~= #plain and #m .. " bytes")
    local cipher = mode.Cipher()
                      .setBlockCipher(algo)
                      .setPadding(padding)
                      .setKey(key)

    ciphertext  = cipher.init()
                      .update( Stream.fromArray( iv ) )
                      .update( Stream.fromHex(m) )
                      .finish()
                      .asHex()
                      :lower()
    done()

    start(desc .. " decrypt", #m ~= #plain and #m .. " bytes")
    local decipher = mode.Decipher()
                      .setBlockCipher(algo)
                      .setPadding(padding)
                      .setKey(key)

    local plaintext = decipher.init()
                      .update( Stream.fromArray( iv ) )
                      .update( Stream.fromHex(ciphertext) )
                      .finish()
                      .asHex()
                      :lower()
    done()

    assert(plaintext == m, plaintext .. ' ~= ' .. m)
end

------------------------------------------------------------

local function perf_base(base)
    local base_n = require ("lockbox.util." .. base)

    local m = plain
    local encoded, decoded

    start(base .. " encoding")
    encoded = base_n.fromString(m)
    done()

    start(base .. " decoding")
    decoded = base_n.toString(encoded)
    done()

    assert(decoded == m)
end

------------------------------------------------------------

print(_VERSION)

pf("Plain text: %d MBytes except where noted", sizemb)
pf("Elapsed time in seconds")

print("\n-- hash digest \n")

perf_digest "md2"
perf_digest "md4"
perf_digest "md5"
perf_digest "sha1"
perf_digest "sha2_224"
perf_digest "sha2_256"
perf_digest "ripemd128"
perf_digest "ripemd160"

print("\n-- hmac digest \n")

perf_hmacdigest "md5"
perf_hmacdigest "sha1"
perf_hmacdigest "sha2_224"
perf_hmacdigest "sha2_256"

print("\n-- block cipher \n")

perf_blockcipher ("des", "ecb", "zero", { key = k8, iv = "", downscale = 2^-4 })
perf_blockcipher ("des", "cbc", "zero", { key = k8, iv = iv8, downscale = 2^-4 })

perf_blockcipher ("aes128", "ecb", "zero", { iv = "", downscale = 2^-2 })
perf_blockcipher ("aes128", "cbc", "zero", { downscale = 2^-2 })
perf_blockcipher ("aes128", "cfb", "zero", { downscale = 2^-2 })
perf_blockcipher ("aes128", "ofb", "zero", { downscale = 2^-2 })
perf_blockcipher ("aes128", "ctr", "zero", { downscale = 2^-2 })
perf_blockcipher ("aes128", "ige", "zero", { iv = iv32, downscale = 2^-2 })
perf_blockcipher ("aes128", "cbc", "pkcs7", { downscale = 2^-2 })

perf_blockcipher ("aes256", "cbc", "zero", { key = k32, downscale = 2^-2 })
perf_blockcipher ("aes256", "ctr", "zero", { key = k32, downscale = 2^-2 })

perf_blockcipher ("tea", "ecb", "zero", { iv = "" })
perf_blockcipher ("tea", "cbc", "zero", { iv = iv8 })
perf_blockcipher ("xtea", "ecb", "zero", { iv = "" })
perf_blockcipher ("xtea", "cbc", "zero", { iv = iv8 })

print("\n-- base<n> encoding \n")

perf_base "base64"
