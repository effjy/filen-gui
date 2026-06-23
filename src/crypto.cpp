#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <argon2.h>

#include <stdexcept>
#include <cstring>

namespace filen {
namespace crypto {

namespace {
const char* kHex = "0123456789abcdef";
const std::string kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
} // namespace

std::string toHex(const Bytes& in) {
    std::string out;
    out.reserve(in.size() * 2);
    for (uint8_t b : in) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

Bytes fromHex(const std::string& hex) {
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("invalid hex");
    };
    if (hex.size() % 2 != 0) throw std::runtime_error("odd hex length");
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>((val(hex[i]) << 4) | val(hex[i + 1])));
    return out;
}

std::string base64Encode(const Bytes& in) {
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(kB64[(n >> 6) & 63]);
        out.push_back(kB64[n & 63]);
    }
    if (i < in.size()) {
        uint32_t n = in[i] << 16;
        bool two = (i + 1 < in.size());
        if (two) n |= in[i + 1] << 8;
        out.push_back(kB64[(n >> 18) & 63]);
        out.push_back(kB64[(n >> 12) & 63]);
        out.push_back(two ? kB64[(n >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

Bytes base64Decode(const std::string& in) {
    int rev[256];
    std::memset(rev, -1, sizeof(rev));
    for (int i = 0; i < 64; ++i) rev[(unsigned char)kB64[i]] = i;
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = rev[(unsigned char)c];
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
}

Bytes sha512(const Bytes& in) {
    Bytes out(SHA512_DIGEST_LENGTH);
    SHA512(in.data(), in.size(), out.data());
    return out;
}

Bytes sha1(const Bytes& in) {
    Bytes out(SHA_DIGEST_LENGTH);
    SHA1(in.data(), in.size(), out.data());
    return out;
}

std::string sha512Hex(const std::string& in) {
    Bytes b(in.begin(), in.end());
    return toHex(sha512(b));
}

std::string sha512HexBytes(const Bytes& in) {
    return toHex(sha512(in));
}

std::string hashFileNameV2(const std::string& nameLower) {
    Bytes nameBytes(nameLower.begin(), nameLower.end());
    std::string sha512hex = toHex(sha512(nameBytes));
    Bytes hexBytes(sha512hex.begin(), sha512hex.end());
    return toHex(sha1(hexBytes));
}

std::string uuidV4() {
    Bytes b(16);
    RAND_bytes(b.data(), 16);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    std::string h = toHex(b);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" +
           h.substr(16, 4) + "-" + h.substr(20, 12);
}

Bytes pbkdf2Sha512(const std::string& password, const std::string& salt,
                   int iterations, int keyLenBytes) {
    Bytes out(keyLenBytes);
    if (PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                          reinterpret_cast<const unsigned char*>(salt.data()),
                          (int)salt.size(), iterations, EVP_sha512(),
                          keyLenBytes, out.data()) != 1)
        throw std::runtime_error("PBKDF2 failed");
    return out;
}

Bytes argon2id(const std::string& password, const Bytes& salt,
               uint32_t t, uint32_t m, uint32_t p, size_t dkLen) {
    Bytes out(dkLen);
    int rc = argon2id_hash_raw(t, m, p, password.data(), password.size(),
                               salt.data(), salt.size(), out.data(), dkLen);
    if (rc != ARGON2_OK)
        throw std::runtime_error(std::string("argon2id failed: ") +
                                 argon2_error_message(rc));
    return out;
}

Bytes aesGcmEncrypt(const Bytes& key, const Bytes& iv, const Bytes& plain) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher ctx");
    Bytes out(plain.size());
    int len = 0, total = 0;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("gcm init");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
            throw std::runtime_error("gcm ivlen");
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("gcm key");
        if (EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), (int)plain.size()) != 1)
            throw std::runtime_error("gcm update");
        total = len;
        if (EVP_EncryptFinal_ex(ctx, out.data() + total, &len) != 1)
            throw std::runtime_error("gcm final");
        total += len;
        out.resize(total);
        Bytes tag(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
            throw std::runtime_error("gcm tag");
        out.insert(out.end(), tag.begin(), tag.end());
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

Bytes aesGcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& cipherWithTag) {
    if (cipherWithTag.size() < 16) throw std::runtime_error("ciphertext too short");
    size_t ctLen = cipherWithTag.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher ctx");
    Bytes out(ctLen);
    int len = 0, total = 0;
    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("gcm init");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
            throw std::runtime_error("gcm ivlen");
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("gcm key");
        if (ctLen &&
            EVP_DecryptUpdate(ctx, out.data(), &len, cipherWithTag.data(), (int)ctLen) != 1)
            throw std::runtime_error("gcm update");
        total = len;
        Bytes tag(cipherWithTag.end() - 16, cipherWithTag.end());
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1)
            throw std::runtime_error("gcm settag");
        if (EVP_DecryptFinal_ex(ctx, out.data() + total, &len) != 1)
            throw std::runtime_error("gcm auth failed");
        total += len;
        out.resize(total);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::string randomAlnum(size_t len) {
    static const char* set =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    Bytes r(len);
    RAND_bytes(r.data(), (int)len);
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) out.push_back(set[r[i] % 62]);
    return out;
}

DerivedAuth deriveAuth(const std::string& rawPassword,
                       const std::string& salt, int authVersion) {
    DerivedAuth d;
    if (authVersion == 2) {
        // PBKDF2-SHA512, 200000 iterations, 512 bit -> 128 hex chars.
        Bytes derived = pbkdf2Sha512(rawPassword, salt, 200000, 64);
        std::string hex = toHex(derived);
        d.masterKey = hex.substr(0, hex.size() / 2);
        std::string half = hex.substr(hex.size() / 2);
        d.derivedPassword = sha512Hex(half);
    } else if (authVersion == 3) {
        Bytes saltBytes = fromHex(salt);
        Bytes derived = argon2id(rawPassword, saltBytes, 3, 65536, 4, 64);
        std::string hex = toHex(derived);
        d.masterKey = hex.substr(0, hex.size() / 2);
        d.derivedPassword = hex.substr(hex.size() / 2);
    } else {
        throw std::runtime_error("Unsupported auth version (only 2 and 3)");
    }
    return d;
}

std::string decryptMetadata(const std::string& metadata, const std::string& key) {
    if (key.empty()) throw std::runtime_error("empty key");
    if (metadata.size() < 3) throw std::runtime_error("metadata too short");
    std::string version = metadata.substr(0, 3);
    if (version == "002") {
        Bytes keyBuf = pbkdf2Sha512(key, key, 1, 32);
        std::string ivStr = metadata.substr(3, 12);
        Bytes iv(ivStr.begin(), ivStr.end());
        Bytes enc = base64Decode(metadata.substr(15));
        Bytes plain = aesGcmDecrypt(keyBuf, iv, enc);
        return std::string(plain.begin(), plain.end());
    } else if (version == "003") {
        if (key.size() != 64) throw std::runtime_error("003 needs 64-char hex key");
        Bytes keyBuf = fromHex(key);
        Bytes iv = fromHex(metadata.substr(3, 24));
        Bytes enc = base64Decode(metadata.substr(27));
        Bytes plain = aesGcmDecrypt(keyBuf, iv, enc);
        return std::string(plain.begin(), plain.end());
    }
    throw std::runtime_error("Unsupported metadata version " + version);
}

std::string encryptMetadata002(const std::string& plaintext, const std::string& key) {
    Bytes keyBuf = pbkdf2Sha512(key, key, 1, 32);
    std::string iv = randomAlnum(12);
    Bytes ivBuf(iv.begin(), iv.end());
    Bytes plain(plaintext.begin(), plaintext.end());
    Bytes enc = aesGcmEncrypt(keyBuf, ivBuf, plain);
    return "002" + iv + base64Encode(enc);
}

Bytes decryptFileData(const Bytes& data, const std::string& key, int version) {
    if (data.size() < 12 + 16) throw std::runtime_error("chunk too short");
    Bytes keyBuf;
    if (version == 2) {
        if (key.size() != 32) throw std::runtime_error("v2 needs 32-char key");
        keyBuf.assign(key.begin(), key.end());
    } else if (version == 3) {
        if (key.size() != 64) throw std::runtime_error("v3 needs 64-char hex key");
        keyBuf = fromHex(key);
    } else {
        throw std::runtime_error("Unsupported file version");
    }
    Bytes iv(data.begin(), data.begin() + 12);
    Bytes cipherWithTag(data.begin() + 12, data.end());
    return aesGcmDecrypt(keyBuf, iv, cipherWithTag);
}

Bytes encryptFileData(const Bytes& data, const std::string& key, int version) {
    Bytes keyBuf, iv;
    if (version == 2) {
        if (key.size() != 32) throw std::runtime_error("v2 needs 32-char key");
        keyBuf.assign(key.begin(), key.end());
        std::string ivStr = randomAlnum(12);
        iv.assign(ivStr.begin(), ivStr.end());
    } else if (version == 3) {
        if (key.size() != 64) throw std::runtime_error("v3 needs 64-char hex key");
        keyBuf = fromHex(key);
        iv.resize(12);
        RAND_bytes(iv.data(), 12);
    } else {
        throw std::runtime_error("Unsupported file version");
    }
    Bytes cipherWithTag = aesGcmEncrypt(keyBuf, iv, data);
    Bytes out;
    out.reserve(iv.size() + cipherWithTag.size());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), cipherWithTag.begin(), cipherWithTag.end());
    return out;
}

} // namespace crypto
} // namespace filen
