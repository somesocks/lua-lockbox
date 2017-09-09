local HMAC = require("lockbox.mac.hmac");

local Stream = require("lockbox.util.stream");
local Array = require("lockbox.util.array");

local HKDF = function()

    local public = {};
    
    local Digest = nil;
    local inputKeyMaterial = nil;
    local salt = nil;
    local info = nil;
    local outputLen = nil;
    
    local hashLen = nil;
    local secret = nil;
    
    local extract = function()
        local res = HMAC()
                        .setDigest(Digest)
                        .setKey(salt)
                        .init()
                        .update(Stream.fromArray(inputKeyMaterial))
                        .finish()
                        .asBytes();
        hashLen = #res;
        return res;
    end
    
    local expand = function(prk)
        local iterations = math.ceil(outputLen / hashLen);
        local mixin = {};
        local results = {};
        local remainingBytes = outputLen;
        
        for i = 1, iterations do
            local mac = HMAC()
                            .setDigest(Digest)
                            .setKey(prk)
                            .init();

            mac.update(Stream.fromArray(mixin));
            if info then
                mac.update(Stream.fromArray(info));
            end
            mac.update(Stream.fromArray({ i }));
            
            local stepResult = mac.finish().asBytes();
            local stepSize = math.min(remainingBytes, #stepResult);

            for j = 1, stepSize do
                results[#results + 1] = stepResult[j];
            end
            
            mixin = stepResult;
            remainingBytes = remainingBytes - stepSize;
        end
        
        return results;
    end
    
    public.setDigest = function(digestModule)
        Digest = digestModule;
        return public;
    end
    
    public.setInputKeyMaterial = function(ikm)
        inputKeyMaterial = ikm;
        return public;
    end
    
    public.setSalt = function(s)
        salt = s;
        return public;
    end
    
    public.setInfo = function(i)
        info = i;
        return public;
    end
    
    public.setOutputLen = function(len)
        outputLen = len;
        return public;
    end
    
    public.finish = function()
        if not salt then
            salt = Array.fromHex("0000000000000000000000000000000000000000");
        end
        local prk = extract(salt, inputKeyMaterial);
        secret = expand(prk, info, outputLength);
        return public;
    end
    
    public.asBytes = function()
        return secret;
    end
    
    public.asHex = function()
        local hex = "";
        for i = 1, #secret do
           hex = hex .. string.format("%02x", secret[i]) 
        end
        return hex;
    end
    
    return public;
end

return HKDF;

