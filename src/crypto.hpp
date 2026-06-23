// Filen GUI - cryptography primitives
// Implements the subset of Filen's end-to-end encryption needed to
// authenticate and to decrypt file/folder metadata and file data.
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace filen {
namespace crypto {

using Bytes = std::vector<uint8_t>;

// Encoding helpers
std::string toHex(const Bytes& in);
Bytes fromHex(const std::string& hex);
std::string base64Encode(const Bytes& in);
Bytes base64Decode(const std::string& in);

// Hashes / KDFs
Bytes sha512(const Bytes& in);
Bytes sha1(const Bytes& in);
std::string sha512Hex(const std::string& in);
std::string sha512HexBytes(const Bytes& in);
// Filen filename hash for auth version 1/2: sha1hex(sha512hex(name.toLowerCase())).
std::string hashFileNameV2(const std::string& nameLower);
// Random UUID v4 string (lower-case, hyphenated).
std::string uuidV4();
Bytes pbkdf2Sha512(const std::string& password, const std::string& salt,
                   int iterations, int keyLenBytes);
// Argon2id (auth version 3). Returns dkLen bytes.
Bytes argon2id(const std::string& password, const Bytes& salt,
               uint32_t t, uint32_t m, uint32_t p, size_t dkLen);

// AES-256-GCM. The authentication tag (16 bytes) is appended to the cipher text.
Bytes aesGcmEncrypt(const Bytes& key, const Bytes& iv, const Bytes& plain);
Bytes aesGcmDecrypt(const Bytes& key, const Bytes& iv, const Bytes& cipherWithTag);

// Random
std::string randomAlnum(size_t len);

// Derived password + master key for a given auth version.
struct DerivedAuth {
    std::string masterKey;       // hex (v2/v3) used as a metadata key
    std::string derivedPassword; // sent to the server
};
DerivedAuth deriveAuth(const std::string& rawPassword,
                       const std::string& salt, int authVersion);

// Metadata (filenames, keys, ...) encryption. Supports the "002" and "003"
// formats. Throws std::runtime_error on failure.
std::string decryptMetadata(const std::string& metadata, const std::string& key);
std::string encryptMetadata002(const std::string& plaintext, const std::string& key);

// File chunk data. version is the Filen FileEncryptionVersion (2 or 3).
Bytes decryptFileData(const Bytes& data, const std::string& key, int version);
Bytes encryptFileData(const Bytes& data, const std::string& key, int version);

} // namespace crypto
} // namespace filen
