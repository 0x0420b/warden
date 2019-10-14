#pragma once

#include <memory>
#include <string>

#include <openssl/bn.h>

namespace shared::crypto
{
    class SHA1;

    class BigNumber
    {
    public:
        BigNumber();
        BigNumber(BigNumber const& bn);
        BigNumber(BigNumber&& bn) noexcept;
        BigNumber(uint32_t value);
		BigNumber(uint8_t const* bytes, int32_t len);
        ~BigNumber();

        void SetDword(uint32_t value);
        void SetQword(uint64_t value);
        void SetBinary(uint8_t const* bytes, int32_t len);
        void SetBinary(SHA1 const& sha1);
        void SetHexStr(char const* str);

        void SetRand(int32_t numbits);

        BigNumber& operator=(BigNumber const& bn);

        BigNumber operator+=(BigNumber const& bn);
        BigNumber operator+(BigNumber const& bn)
        {
            BigNumber t(*this);
            return t += bn;
        }

        BigNumber operator-=(BigNumber const& bn);
        BigNumber operator-(BigNumber const& bn)
        {
            BigNumber t(*this);
            return t -= bn;
        }

        BigNumber operator*=(BigNumber const& bn);
        BigNumber operator*(BigNumber const& bn)
        {
            BigNumber t(*this);
            return t *= bn;
        }

        BigNumber operator/=(BigNumber const& bn);
        BigNumber operator/(BigNumber const& bn)
        {
            BigNumber t(*this);
            return t /= bn;
        }

        BigNumber operator%=(BigNumber const& bn);
        BigNumber operator%(BigNumber const& bn)
        {
            BigNumber t(*this);
            return t %= bn;
        }

		bool operator == (BigNumber const& bn) const;
		bool operator != (BigNumber const& bn) const {
			return !(operator == (bn));
		}

        bool IsZero() const;
        bool IsNegative() const;

        BigNumber ModExp(BigNumber const& bn1, BigNumber const& bn2);
        BigNumber Exp(BigNumber const&);

        int32_t GetNumBytes(void) const;

        struct bignum_st *BN() { return _bn; }

        uint32_t AsDword() const;

        std::unique_ptr<uint8_t[]> AsByteArray(int32_t minSize = 0, bool littleEndian = true) const;

        std::string AsHexStr() const;
        std::string AsDecStr() const;

    private:
        struct bignum_st *_bn;

    };

} // namespace crypto