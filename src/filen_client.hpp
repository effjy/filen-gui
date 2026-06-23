// Filen GUI - high level Filen.io API client.
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <stdexcept>

namespace filen {

struct Item {
    bool isFolder = false;
    std::string uuid;
    std::string name;
    uint64_t size = 0;          // files only
    int64_t lastModified = 0;   // ms, files only
    std::string mime;           // files only
    // File payload location / decryption parameters:
    std::string region;
    std::string bucket;
    std::string fileKey;        // decryption key from metadata
    int chunks = 0;
    int version = 0;            // FileEncryptionVersion
};

// Thrown for any API or crypto error with a human readable message.
struct FilenError : std::runtime_error {
    explicit FilenError(const std::string& m) : std::runtime_error(m) {}
};

class Client {
public:
    Client();
    ~Client();

    // Authenticate. twoFactorCode may be empty when 2FA is disabled.
    // Throws FilenError on failure (bad credentials, 2FA required, ...).
    void login(const std::string& email, const std::string& password,
               const std::string& twoFactorCode);

    bool loggedIn() const { return !apiKey_.empty(); }
    const std::string& baseFolderUuid() const { return baseFolderUuid_; }
    const std::string& email() const { return email_; }

    // List the contents of a folder (decrypted names/metadata).
    std::vector<Item> listDir(const std::string& uuid);

    // Download a file to destPath. progress(done,total) is called periodically.
    void downloadFile(const Item& file, const std::string& destPath,
                      const std::function<void(uint64_t, uint64_t)>& progress);

    // Upload a local file into the folder identified by parentUuid. The stored
    // name defaults to the local file's base name. progress(done,total) is
    // called as chunks are uploaded.
    void uploadFile(const std::string& parentUuid, const std::string& localPath,
                    const std::function<void(uint64_t, uint64_t)>& progress);

    // Move a file or folder to the trash.
    void trashItem(const Item& item);

    // Number of items currently in the trash (files + folders).
    int trashCount();
    // Permanently delete everything in the trash.
    void emptyTrash();

private:
    // Low level HTTP. Returns the unwrapped "data" object of the response.
    // Throws FilenError when status==false.
    std::string postJson(const std::string& endpoint, const std::string& body,
                         bool auth);
    std::string getRaw(const std::string& url, bool auth);
    std::vector<uint8_t> getBinary(const std::string& url, bool auth);

    std::string apiKey_;
    std::string email_;
    std::vector<std::string> masterKeys_;
    std::string baseFolderUuid_;
    int authVersion_ = 0;
};

} // namespace filen
