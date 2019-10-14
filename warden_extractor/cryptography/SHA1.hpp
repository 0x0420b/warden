#pragma once

#include <string>
#include <type_traits>

#include <openssl/sha.h>

#include "cryptography/BigNumber.hpp"

namespace shared::crypto
{
    class SHA1
    {
    public:
        typedef std::integral_constant<uint32_t, SHA_DIGEST_LENGTH> DigestLength;

        SHA1(SHA1 const& other);
        SHA1();
        ~SHA1();

        template <typename T, typename... Args, typename std::enable_if<std::is_same<T, BigNumber>::value, int>::type = 0>
        void UpdateBigNumbers(T const& bn0, Args&&... args)
        {
            UpdateData(bn0.AsByteArray().get(), bn0.GetNumBytes());
            UpdateBigNumbers(std::forward<Args>(args)...);
        }

        template <typename T, typename std::enable_if<std::is_same<T, BigNumber>::value, int>::type = 0>
        void UpdateBigNumbers(T const& bn0)
        {
            UpdateData(bn0.AsByteArray().get(), bn0.GetNumBytes());
        }

        template <typename T, size_t N>
        void UpdateData(std::array<T, N>& arr)
        {
            static_assert(std::is_standard_layout<T>::value, "T must be a simple data type");
            UpdateData(reinterpret_cast<uint8_t*>(arr.data()), N * sizeof(T));
        }

        void UpdateData(const uint8_t *dta, int len);
        void UpdateData(char c);
        void UpdateData(const std::string &str);

        void Initialize(const char* label);
        void Initialize();
        void Finalize();

        uint8_t* GetDigest() const { return (uint8_t*)mDigest; }
        int GetLength() const { return SHA_DIGEST_LENGTH; }

    private:
        SHAstate_st mC;
        uint8_t mDigest[SHA_DIGEST_LENGTH];
    };
} // wowgm::cryptography

