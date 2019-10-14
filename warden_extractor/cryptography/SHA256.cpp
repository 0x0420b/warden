#include "cryptography/SHA256.hpp"

#include <cstring>
#include <openssl/sha.h>

namespace shared::crypto
{
    SHA256::SHA256(SHA256 const& other)
    {
        SHA256_Init(&mC);
        memcpy(&mC, &other.mC, sizeof(SHA256_CTX));
        memcpy(mDigest, other.mDigest, SHA_DIGEST_LENGTH);
    }

    SHA256::SHA256()
    {
        SHA256_Init(&mC);
        memset(mDigest, 0, SHA_DIGEST_LENGTH * sizeof(uint8_t));
    }

    SHA256::~SHA256()
    {
        SHA256_Init(&mC);
    }

    void SHA256::UpdateData(const uint8_t *dta, int len)
    {
        SHA256_Update(&mC, dta, len);
    }

    void SHA256::UpdateData(const std::string &str)
    {
        UpdateData((uint8_t const*)str.c_str(), str.length());
    }

    void SHA256::UpdateData(char c)
    {
        UpdateData((uint8_t const*)&c, 1);
    }

    void SHA256::Initialize(const char* label)
    {
        SHA256_Init(&mC);
        memset(mDigest, 0, SHA_DIGEST_LENGTH * sizeof(uint8_t));
    }

    void SHA256::Initialize()
    {
        SHA256_Init(&mC);
        memset(mDigest, 0, SHA_DIGEST_LENGTH * sizeof(uint8_t));
    }

    void SHA256::Finalize()
    {
        SHA256_Final(mDigest, &mC);
    }

} // namespace shared::crypto
