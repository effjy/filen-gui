#include "filen_client.hpp"
#include "crypto.hpp"
#include "vendor/json.hpp"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <stdexcept>
#include <mutex>
#include <algorithm>

using json = nlohmann::json;

namespace filen {

namespace {
const char* kGateway = "https://gateway.filen.io";
const char* kEgest = "https://egest.filen.io";
const char* kIngest = "https://ingest.filen.io";
constexpr size_t kChunkSize = 1024 * 1024;

std::string guessMime(const std::string& name) {
    auto dot = name.find_last_of('.');
    std::string ext = dot == std::string::npos ? "" : name.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    static const std::pair<const char*, const char*> table[] = {
        {"txt", "text/plain"}, {"pdf", "application/pdf"}, {"png", "image/png"},
        {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"gif", "image/gif"},
        {"webp", "image/webp"}, {"svg", "image/svg+xml"}, {"mp3", "audio/mpeg"},
        {"mp4", "video/mp4"}, {"webm", "video/webm"}, {"zip", "application/zip"},
        {"7z", "application/x-7z-compressed"}, {"json", "application/json"},
        {"html", "text/html"}, {"csv", "text/csv"}, {"doc", "application/msword"},
        {"xml", "application/xml"}, {"gz", "application/gzip"},
    };
    for (auto& e : table) if (ext == e.first) return e.second;
    return "application/octet-stream";
}

std::once_flag g_curlInit;

size_t writeCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}
size_t writeBinCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::vector<uint8_t>*>(userdata);
    out->insert(out->end(), ptr, ptr + size * nmemb);
    return size * nmemb;
}
} // namespace

Client::Client() {
    std::call_once(g_curlInit, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}
Client::~Client() = default;

static std::string performGet(const std::string& url,
                              const std::string& bearer, bool binary,
                              std::string* textOut,
                              std::vector<uint8_t>* binOut) {
    CURL* curl = curl_easy_init();
    if (!curl) throw FilenError("curl init failed");
    struct curl_slist* headers = nullptr;
    if (!bearer.empty())
        headers = curl_slist_append(headers, ("Authorization: Bearer " + bearer).c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (binary) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeBinCb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, binOut);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, textOut);
    }
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "filen-gui/1.0");
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw FilenError(std::string("network error: ") + curl_easy_strerror(rc));
    if (code >= 400)
        throw FilenError("HTTP error " + std::to_string(code));
    return {};
}

std::string Client::getRaw(const std::string& url, bool auth) {
    std::string out;
    performGet(url, auth ? apiKey_ : "", false, &out, nullptr);
    return out;
}

std::vector<uint8_t> Client::getBinary(const std::string& url, bool auth) {
    std::vector<uint8_t> out;
    performGet(url, auth ? apiKey_ : "", true, nullptr, &out);
    return out;
}

std::string Client::postJson(const std::string& endpoint, const std::string& body,
                             bool auth) {
    CURL* curl = curl_easy_init();
    if (!curl) throw FilenError("curl init failed");
    std::string response;
    std::string url = std::string(kGateway) + endpoint;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (auth && !apiKey_.empty())
        headers = curl_slist_append(headers, ("Authorization: Bearer " + apiKey_).c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "filen-gui/1.0");
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw FilenError(std::string("network error: ") + curl_easy_strerror(rc));

    json j;
    try {
        j = json::parse(response);
    } catch (const std::exception&) {
        throw FilenError("invalid server response");
    }
    if (j.contains("status") && j["status"].is_boolean() && !j["status"].get<bool>()) {
        std::string msg = j.value("message", "request failed");
        throw FilenError(msg);
    }
    if (j.contains("data")) return j["data"].dump();
    return j.dump();
}

void Client::login(const std::string& email, const std::string& password,
                   const std::string& twoFactorCode) {
    email_ = email;
    apiKey_.clear();
    masterKeys_.clear();

    // 1. auth info -> salt + auth version
    json infoReq = {{"email", email}};
    json info = json::parse(postJson("/v3/auth/info", infoReq.dump(), false));
    authVersion_ = info.value("authVersion", 0);
    std::string salt = info.value("salt", "");

    auto derived = crypto::deriveAuth(password, salt, authVersion_);

    // 2. login
    json loginReq = {
        {"email", email},
        {"password", derived.derivedPassword},
        {"twoFactorCode", twoFactorCode.empty() ? "XXXXXX" : twoFactorCode},
        {"authVersion", authVersion_}};
    json login = json::parse(postJson("/v3/login", loginReq.dump(), false));
    apiKey_ = login.value("apiKey", "");
    if (apiKey_.empty()) throw FilenError("login failed: no API key returned");

    // 3. resolve master keys
    if (authVersion_ == 2) {
        masterKeys_.push_back(derived.masterKey);
        // Best effort: sync the full master key list from the server.
        try {
            std::string enc = crypto::encryptMetadata002(derived.masterKey, derived.masterKey);
            json req = {{"masterKeys", enc}};
            json resp = json::parse(postJson("/v3/user/masterKeys", req.dump(), true));
            std::string encKeys = resp.value("keys", "");
            if (!encKeys.empty()) {
                std::string decoded = crypto::decryptMetadata(encKeys, derived.masterKey);
                size_t pos = 0;
                while (pos < decoded.size()) {
                    size_t sep = decoded.find('|', pos);
                    std::string k = decoded.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);
                    if (!k.empty()) {
                        bool exists = false;
                        for (auto& e : masterKeys_) if (e == k) exists = true;
                        if (!exists) masterKeys_.push_back(k);
                    }
                    if (sep == std::string::npos) break;
                    pos = sep + 1;
                }
            }
        } catch (const std::exception&) {
            // Keep the single derived key; sufficient for most accounts.
        }
    } else if (authVersion_ == 3) {
        // The derived key encrypts the data encryption key (DEK).
        std::string dek;
        json dekResp = json::parse(getRaw(std::string(kGateway) + "/v3/user/dek", true));
        if (dekResp.contains("data") && dekResp["data"].contains("dek") &&
            dekResp["data"]["dek"].is_string()) {
            std::string encDek = dekResp["data"]["dek"].get<std::string>();
            dek = crypto::decryptMetadata(encDek, derived.masterKey);
        } else {
            throw FilenError("could not retrieve data encryption key");
        }
        masterKeys_.push_back(dek);
    } else {
        throw FilenError("unsupported auth version " + std::to_string(authVersion_));
    }

    // 4. base folder (GET, response is wrapped in "data")
    json baseResp = json::parse(getRaw(std::string(kGateway) + "/v3/user/baseFolder", true));
    if (baseResp.contains("data") && baseResp["data"].contains("uuid"))
        baseFolderUuid_ = baseResp["data"].value("uuid", "");
    if (baseFolderUuid_.empty()) throw FilenError("could not get base folder");
}

std::vector<Item> Client::listDir(const std::string& uuid) {
    json req = {{"uuid", uuid}};
    json data = json::parse(postJson("/v3/dir/content", req.dump(), true));

    std::vector<Item> result;

    if (data.contains("folders") && data["folders"].is_array()) {
        for (auto& f : data["folders"]) {
            Item it;
            it.isFolder = true;
            it.uuid = f.value("uuid", "");
            std::string nameMeta = f.value("name", "");
            it.name = "[encrypted]";
            for (auto& key : masterKeys_) {
                try {
                    std::string dec = crypto::decryptMetadata(nameMeta, key);
                    json nj = json::parse(dec);
                    if (nj.contains("name") && nj["name"].is_string()) {
                        it.name = nj["name"].get<std::string>();
                        break;
                    }
                } catch (const std::exception&) { continue; }
            }
            result.push_back(std::move(it));
        }
    }

    if (data.contains("uploads") && data["uploads"].is_array()) {
        for (auto& u : data["uploads"]) {
            Item it;
            it.isFolder = false;
            it.uuid = u.value("uuid", "");
            it.region = u.value("region", "");
            it.bucket = u.value("bucket", "");
            it.chunks = u.value("chunks", 0);
            it.version = u.value("version", 0);
            std::string meta = u.value("metadata", "");
            it.name = "[encrypted]";
            for (auto& key : masterKeys_) {
                try {
                    std::string dec = crypto::decryptMetadata(meta, key);
                    json mj = json::parse(dec);
                    if (mj.contains("name") && mj["name"].is_string() &&
                        !mj["name"].get<std::string>().empty()) {
                        it.name = mj["name"].get<std::string>();
                        it.fileKey = mj.value("key", "");
                        it.mime = mj.value("mime", "application/octet-stream");
                        if (mj.contains("size")) {
                            if (mj["size"].is_number()) it.size = mj["size"].get<uint64_t>();
                            else if (mj["size"].is_string()) it.size = std::stoull(mj["size"].get<std::string>());
                        }
                        if (mj.contains("lastModified")) {
                            if (mj["lastModified"].is_number()) it.lastModified = mj["lastModified"].get<int64_t>();
                            else if (mj["lastModified"].is_string()) it.lastModified = std::stoll(mj["lastModified"].get<std::string>());
                        }
                        break;
                    }
                } catch (const std::exception&) { continue; }
            }
            result.push_back(std::move(it));
        }
    }
    return result;
}

void Client::downloadFile(const Item& file, const std::string& destPath,
                          const std::function<void(uint64_t, uint64_t)>& progress) {
    if (file.fileKey.empty())
        throw FilenError("file key unavailable (could not decrypt metadata)");
    FILE* out = fopen(destPath.c_str(), "wb");
    if (!out) throw FilenError("cannot open destination file");

    uint64_t total = file.size;
    uint64_t done = 0;
    try {
        for (int i = 0; i < file.chunks; ++i) {
            std::string url = std::string(kEgest) + "/" + file.region + "/" +
                              file.bucket + "/" + file.uuid + "/" + std::to_string(i);
            std::vector<uint8_t> enc = getBinary(url, true);
            if (enc.empty()) continue;
            std::vector<uint8_t> plain =
                crypto::decryptFileData(enc, file.fileKey, file.version);
            if (!plain.empty() &&
                fwrite(plain.data(), 1, plain.size(), out) != plain.size())
                throw FilenError("write error");
            done += plain.size();
            if (progress) progress(done, total ? total : done);
        }
    } catch (...) {
        fclose(out);
        throw;
    }
    fclose(out);
    if (progress) progress(done, done);
}

void Client::trashItem(const Item& item) {
    json req = {{"uuid", item.uuid}};
    postJson(item.isFolder ? "/v3/dir/trash" : "/v3/file/trash", req.dump(), true);
}

int Client::trashCount() {
    json req = {{"uuid", "trash"}};
    json data = json::parse(postJson("/v3/dir/content", req.dump(), true));
    int count = 0;
    if (data.contains("folders") && data["folders"].is_array()) count += (int)data["folders"].size();
    if (data.contains("uploads") && data["uploads"].is_array()) count += (int)data["uploads"].size();
    return count;
}

void Client::emptyTrash() {
    postJson("/v3/trash/empty", "{}", true);
}

// POST a binary body to an absolute URL with extra headers. Returns the body.
static std::string performPostBinary(const std::string& url,
                                     const std::vector<uint8_t>& body,
                                     const std::vector<std::string>& extraHeaders,
                                     const std::string& bearer) {
    CURL* curl = curl_easy_init();
    if (!curl) throw FilenError("curl init failed");
    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    headers = curl_slist_append(headers, "Accept: application/json, text/plain, */*");
    if (!bearer.empty())
        headers = curl_slist_append(headers, ("Authorization: Bearer " + bearer).c_str());
    for (const auto& h : extraHeaders) headers = curl_slist_append(headers, h.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.empty() ? "" : (const char*)body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "filen-gui/1.0");
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw FilenError(std::string("network error: ") + curl_easy_strerror(rc));
    if (code >= 400) throw FilenError("upload HTTP error " + std::to_string(code));
    return response;
}

void Client::uploadFile(const std::string& parentUuid, const std::string& localPath,
                        const std::function<void(uint64_t, uint64_t)>& progress) {
    if (masterKeys_.empty()) throw FilenError("not logged in");

    FILE* in = fopen(localPath.c_str(), "rb");
    if (!in) throw FilenError("cannot open file");

    struct stat st{};
    int64_t lastModified = 0;
    if (stat(localPath.c_str(), &st) == 0)
        lastModified = (int64_t)st.st_mtime * 1000;

    fseek(in, 0, SEEK_END);
    long sz = ftell(in);
    fseek(in, 0, SEEK_SET);
    if (sz < 0) { fclose(in); throw FilenError("cannot determine file size"); }
    uint64_t fileSize = (uint64_t)sz;

    std::string fileName = localPath;
    auto slash = fileName.find_last_of('/');
    if (slash != std::string::npos) fileName = fileName.substr(slash + 1);
    std::string mime = guessMime(fileName);

    const int version = 2;
    std::string key = crypto::randomAlnum(32);
    std::string rm = crypto::randomAlnum(32);
    std::string uploadKey = crypto::randomAlnum(32);
    std::string uuid = crypto::uuidV4();
    int chunks = fileSize == 0 ? 0 : (int)((fileSize + kChunkSize - 1) / kChunkSize);

    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha512(), nullptr);

    uint64_t done = 0;
    try {
        for (int i = 0; i < chunks; ++i) {
            std::vector<uint8_t> buf(kChunkSize);
            size_t n = fread(buf.data(), 1, kChunkSize, in);
            buf.resize(n);
            EVP_DigestUpdate(md, buf.data(), buf.size());

            std::vector<uint8_t> enc = crypto::encryptFileData(buf, key, version);
            std::string bufHash = crypto::sha512HexBytes(enc);
            std::string idx = std::to_string(i);

            std::string params = "uuid=" + uuid + "&index=" + idx + "&parent=" +
                                 parentUuid + "&uploadKey=" + uploadKey + "&hash=" + bufHash;
            std::string url = std::string(kIngest) + "/v3/upload?" + params;

            // Checksum = sha512hex of the query params serialised as an ordered JSON object.
            std::string checkJson = "{\"uuid\":\"" + uuid + "\",\"index\":\"" + idx +
                                    "\",\"parent\":\"" + parentUuid + "\",\"uploadKey\":\"" +
                                    uploadKey + "\",\"hash\":\"" + bufHash + "\"}";
            std::string checksum = crypto::sha512Hex(checkJson);

            std::string resp = performPostBinary(url, enc, {"Checksum: " + checksum}, apiKey_);
            try {
                json j = json::parse(resp);
                if (j.contains("status") && j["status"].is_boolean() && !j["status"].get<bool>())
                    throw FilenError(j.value("message", "chunk upload failed"));
            } catch (const json::exception&) { /* non-JSON success body is fine */ }

            done += n;
            if (progress) progress(done, fileSize ? fileSize : done);
        }
    } catch (...) {
        EVP_MD_CTX_free(md);
        fclose(in);
        throw;
    }
    fclose(in);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_DigestFinal_ex(md, digest, &digestLen);
    EVP_MD_CTX_free(md);
    std::string fileHash = crypto::toHex(std::vector<uint8_t>(digest, digest + digestLen));

    const std::string& masterKey = masterKeys_.back();
    std::string nameEnc = crypto::encryptMetadata002(fileName, key);
    std::string mimeEnc = crypto::encryptMetadata002(mime, key);
    std::string sizeEnc = crypto::encryptMetadata002(std::to_string(fileSize), key);

    json meta = {{"name", fileName}, {"size", fileSize}, {"mime", mime},
                 {"key", key}, {"lastModified", lastModified}, {"hash", fileHash}};
    std::string metadata = crypto::encryptMetadata002(meta.dump(), masterKey);

    std::string lower = fileName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::string nameHashed = crypto::hashFileNameV2(lower);

    if (fileSize > 0) {
        json req = {{"uuid", uuid}, {"name", nameEnc}, {"nameHashed", nameHashed},
                    {"size", sizeEnc}, {"chunks", chunks}, {"mime", mimeEnc},
                    {"rm", rm}, {"metadata", metadata}, {"version", version},
                    {"uploadKey", uploadKey}};
        postJson("/v3/upload/done", req.dump(), true);
    } else {
        json req = {{"uuid", uuid}, {"name", nameEnc}, {"nameHashed", nameHashed},
                    {"size", sizeEnc}, {"parent", parentUuid}, {"mime", mimeEnc},
                    {"metadata", metadata}, {"version", version}};
        postJson("/v3/upload/empty", req.dump(), true);
    }
    if (progress) progress(fileSize, fileSize);
}

} // namespace filen
