#include "cryptography/HmacHash.hpp"
#include "cryptography/BigNumber.hpp"

#include <cstring>

namespace shared::crypto
{

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX* HMAC_CTX_new()
    {
        HMAC_CTX *ctx = new HMAC_CTX();
        HMAC_CTX_init(ctx);
        return ctx;
    }

    void HMAC_CTX_free(HMAC_CTX* ctx)
    {
        HMAC_CTX_cleanup(ctx);
        delete ctx;
    }
#endif

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    HmacHash<HashCreator, DigestLength>::HmacHash(uint32_t len, uint8_t const* seed) : _ctx(HMAC_CTX_new())
    {
        HMAC_Init_ex(_ctx, seed, len, HashCreator(), nullptr);
        memset(_digest, 0, DigestLength);
    }

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    HmacHash<HashCreator, DigestLength>::~HmacHash()
    {
        HMAC_CTX_free(_ctx);
    }

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    void HmacHash<HashCreator, DigestLength>::UpdateData(std::string const& str)
    {
        HMAC_Update(_ctx, reinterpret_cast<uint8_t const*>(str.c_str()), str.length());
    }

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    void HmacHash<HashCreator, DigestLength>::UpdateData(uint8_t const* data, size_t len)
    {
        HMAC_Update(_ctx, data, len);
    }

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    void HmacHash<HashCreator, DigestLength>::Finalize()
    {
        uint32_t length = 0;
        HMAC_Final(_ctx, _digest, &length);
    }

    template<HashCreateFn HashCreator, uint32_t DigestLength>
    uint8_t* HmacHash<HashCreator, DigestLength>::ComputeHash(BigNumber const& bn)
    {
        HMAC_Update(_ctx, bn.AsByteArray().get(), bn.GetNumBytes());
        Finalize();
        return _digest;
    }

    template class HmacHash<EVP_sha1, SHA_DIGEST_LENGTH>;
    template class HmacHash<EVP_sha256, SHA256_DIGEST_LENGTH>;

} // namespace crypto
