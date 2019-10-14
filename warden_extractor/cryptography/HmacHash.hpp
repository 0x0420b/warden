#pragma once

#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace shared::crypto
{
    class BigNumber;

#define SEED_KEY_SIZE 16

    typedef EVP_MD const* (*HashCreateFn)();

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    class HmacHash
    {
    public:
        HmacHash(uint32_t len, uint8_t const* seed);
        ~HmacHash();

        void UpdateData(std::string const& str);
        void UpdateData(uint8_t const* data, size_t len);
        void Finalize();

        uint8_t* ComputeHash(BigNumber const& bn);
        uint8_t* GetDigest() { return _digest; }
        uint32_t GetLength() const { return DigestLength; }

    private:
        HMAC_CTX* _ctx;
        uint8_t _digest[DigestLength];
    };

    typedef HmacHash<EVP_sha1, SHA_DIGEST_LENGTH> HmacSha1;
    typedef HmacHash<EVP_sha256, SHA256_DIGEST_LENGTH> HmacSha256;

} // namespace crypto
