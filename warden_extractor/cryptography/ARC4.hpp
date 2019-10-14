#pragma once

#include <openssl/evp.h>
#include <cstdint>

namespace shared::crypto
{
    class ARC4
    {
        public:
            ARC4(uint32_t len);
            ARC4(uint8_t const* seed, uint32_t length);
            ~ARC4();

            void Init(uint8_t* seed);
            void UpdateData(size_t len, uint8_t* data);

        private:
            EVP_CIPHER_CTX* m_ctx;
    };
}
