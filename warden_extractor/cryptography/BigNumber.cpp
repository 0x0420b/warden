#include "cryptography/BigNumber.hpp"
#include "cryptography/SHA1.hpp"

#include <openssl/bn.h>
#include <cstring>
#include <algorithm>
#include <memory>

namespace shared::crypto
{

    BigNumber::BigNumber() : _bn(BN_new())
    {
    }

    BigNumber::BigNumber(BigNumber const& bn) : _bn(BN_dup(bn._bn))
    {
    }


    BigNumber::BigNumber(BigNumber&& bn) noexcept : _bn(BN_dup(bn._bn))
    {
        BN_zero(bn._bn);
    }

	BigNumber::BigNumber(uint8_t const* bytes, int32_t len) : _bn(BN_new()) {
		SetBinary(bytes, len);
	}

    BigNumber::BigNumber(uint32_t val)
        : _bn(BN_new())
    {
        BN_set_word(_bn, val);
    }

    BigNumber::~BigNumber()
    {
        BN_free(_bn);
    }

    void BigNumber::SetDword(uint32_t val)
    {
        BN_set_word(_bn, val);
    }

    void BigNumber::SetQword(uint64_t val)
    {
        BN_set_word(_bn, uint32_t(val >> 32));
        BN_lshift(_bn, _bn, 32);
        BN_add_word(_bn, uint32_t(val & 0xFFFFFFFF));
    }

    void BigNumber::SetBinary(SHA1 const& sha1)
    {
        SetBinary(sha1.GetDigest(), sha1.GetLength());
    }

    void BigNumber::SetBinary(uint8_t const* bytes, int32_t len)
    {
        uint8_t* array = new uint8_t[len];

        for (int i = 0; i < len; i++)
            array[i] = bytes[len - 1 - i];

        BN_bin2bn(array, len, _bn);

        delete[] array;
    }

    void BigNumber::SetHexStr(char const* str)
    {
        BN_hex2bn(&_bn, str);
    }

    void BigNumber::SetRand(int32_t numbits)
    {
        BN_rand(_bn, numbits, 0, 1);
    }

    BigNumber& BigNumber::operator = (BigNumber const& bn)
    {
        if (this == &bn)
            return *this;

        BN_copy(_bn, bn._bn);
        return *this;
    }

    BigNumber BigNumber::operator += (BigNumber const& bn)
    {
        BN_add(_bn, _bn, bn._bn);
        return *this;
    }

    BigNumber BigNumber::operator -= (BigNumber const& bn)
    {
        BN_sub(_bn, _bn, bn._bn);
        return *this;
    }

	bool BigNumber::operator == (BigNumber const& bn) const {
		BIGNUM *bnctx = BN_dup(bn._bn);
		BN_sub(bnctx, bnctx, bn._bn);
		bool isZero = BN_is_zero(bnctx);
		BN_free(bnctx);
		return isZero;
	}

    BigNumber BigNumber::operator *= (BigNumber const& bn)
    {
        BN_CTX *bnctx;

        bnctx = BN_CTX_new();
        BN_mul(_bn, _bn, bn._bn, bnctx);
        BN_CTX_free(bnctx);

        return *this;
    }

    BigNumber BigNumber::operator /= (BigNumber const& bn)
    {
        BN_CTX *bnctx;

        bnctx = BN_CTX_new();
        BN_div(_bn, NULL, _bn, bn._bn, bnctx);
        BN_CTX_free(bnctx);

        return *this;
    }

    BigNumber BigNumber::operator %= (BigNumber const& bn)
    {
        BN_CTX *bnctx;

        bnctx = BN_CTX_new();
        BN_mod(_bn, _bn, bn._bn, bnctx);
        BN_CTX_free(bnctx);

        return *this;
    }

    BigNumber BigNumber::Exp(BigNumber const& bn)
    {
        BigNumber ret;
        BN_CTX *bnctx;

        bnctx = BN_CTX_new();
        BN_exp(ret._bn, _bn, bn._bn, bnctx);
        BN_CTX_free(bnctx);

        return ret;
    }

    BigNumber BigNumber::ModExp(BigNumber const& bn1, BigNumber const& bn2)
    {
        BigNumber ret;
        BN_CTX *bnctx;

        bnctx = BN_CTX_new();
        BN_mod_exp(ret._bn, _bn, bn1._bn, bn2._bn, bnctx);
        BN_CTX_free(bnctx);

        return ret;
    }

    int32_t BigNumber::GetNumBytes() const
    {
        return BN_num_bytes(_bn);
    }

    uint32_t BigNumber::AsDword() const
    {
        return (uint32_t)BN_get_word(_bn);
    }

    bool BigNumber::IsZero() const
    {
        return BN_is_zero(_bn);
    }

    bool BigNumber::IsNegative() const
    {
        return BN_is_negative(_bn);
    }

    std::unique_ptr<uint8_t[]> BigNumber::AsByteArray(int32_t minSize, bool littleEndian) const
    {
        int numBytes = GetNumBytes();
        int length = (minSize >= numBytes) ? minSize : numBytes;

        uint8_t* array = new uint8_t[length];

        // If we need more bytes than length of BigNumber set the rest to 0
        if (length > numBytes)
            memset((void*)array, 0, length);

        BN_bn2bin(_bn, (unsigned char *)array);

        // openssl's BN stores data internally in big endian format, reverse if little endian desired
        if (littleEndian)
            std::reverse(array, array + numBytes);

        std::unique_ptr<uint8_t[]> ret(array);
        return ret;
    }

    std::string BigNumber::AsHexStr() const
    {
        char* ch = BN_bn2hex(_bn);
        std::string ret = ch;
        OPENSSL_free(ch);
        return ret;
    }

    std::string BigNumber::AsDecStr() const
    {
        char* ch = BN_bn2dec(_bn);
        std::string ret = ch;
        OPENSSL_free(ch);
        return ret;
    }

} // namespace crypto
