#include <iomanip>
#include <sstream>

#include <fmt/core.h>

#include "CryptoUtils.h"

using namespace std::string_literals;

namespace ash
{

namespace crypto
{

// sha256 of any string data
std::string SHA256(std::string_view data)
{
    std::string digest;
    CryptoPP::SHA256 hash;

    auto ptr = reinterpret_cast<const CryptoPP::byte*>(data.data());
    CryptoPP::StringSource temp(ptr, data.size(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest), false)));

    return digest;
}

CryptoPP::Integer SHA256Int(std::string_view data)
{
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];

    auto ptr = reinterpret_cast<const CryptoPP::byte*>(data.data());
    hash.CalculateDigest(digest, ptr, data.size());

    return CryptoPP::Integer{ digest, CryptoPP::SHA256::DIGESTSIZE };
}

// sha256 of a hex string
std::string SHA256HexString(std::string_view data)
{
    std::string digest;
    CryptoPP::SHA256 hash;

    auto ptr = reinterpret_cast<const CryptoPP::byte*>(data.data());
    CryptoPP::StringSource temp(ptr, data.size(), true,
        new CryptoPP::HexDecoder(
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest), false))));

    return digest;
}

std::string RIPEMD160HexString(std::string_view data)
{
    std::string digest;
    CryptoPP::RIPEMD160 hash;

    auto ptr = reinterpret_cast<const CryptoPP::byte*>(data.data());
    CryptoPP::StringSource temp(ptr, data.size(), true,
        new CryptoPP::HexDecoder(
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest), false))));

    return digest;
}

constexpr auto base_count = 58u;
constexpr std::string_view base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string Base58Encode(CryptoPP::Integer num)
{
    std::string encoded; 
    CryptoPP::Integer mod;
    while (num >= base_count)
    {
        CryptoPP::Integer div = num / base_count;
        mod = (num - (base_count * div));
        encoded = base58Alphabet[mod.ConvertToLong()] + encoded;
        num = div;
    }
    encoded = base58Alphabet[num.ConvertToLong()] + encoded;
    return encoded;
}

using FieldType = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

std::string GetPublicKey(std::string_view privateKeyStr)
{
    FieldType::PrivateKey privateKey;

    CryptoPP::HexDecoder decoder;
    decoder.Put(reinterpret_cast<const CryptoPP::byte*>(privateKeyStr.data()), privateKeyStr.size());
    decoder.MessageEnd();

    CryptoPP::Integer x;
    x.Decode(decoder, decoder.MaxRetrievable());

    privateKey.Initialize(CryptoPP::ASN1::secp256k1(), x);
    
    FieldType::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    const CryptoPP::ECP::Point& q = publicKey.GetPublicElement();

    std::stringstream ssx;
    ssx << std::hex << q.x;
    std::string qx = ssx.str();
    qx.pop_back();
    qx = fmt::format("{:0>64}", qx);

    std::stringstream ssy;
    ssy << std::hex << q.y;
    std::string qy = ssy.str();
    qy.pop_back();
    qy = fmt::format("{:0>64}", qy);

    return fmt::format("04{}{}",qx,qy);
}

std::string GetAddressFromPrivateKey(std::string_view privateKeyStr)
{
    // 1 - Public ECDSA Key
    const auto publicKey = ash::crypto::GetPublicKey(privateKeyStr);

    // 2 - SHA-256 hash of 1
    const auto publicKeyHash = ash::crypto::SHA256HexString(publicKey);

    // 3 - RIPEMD-160 Hash of 2
    const auto ripeHash = ash::crypto::RIPEMD160HexString(publicKeyHash);

    //4 - Adding network bytes to 3
    const auto step4 = "00"s + ripeHash;

    // 5 - SHA-256 hash of 4
    auto networkBytesHash = ash::crypto::SHA256HexString(step4);

    // 6 - SHA-256 hash of 5
    networkBytesHash = ash::crypto::SHA256HexString(networkBytesHash);

    // 7 - First four bytes of 6
    const auto step7 = networkBytesHash.substr(0, 8);

    // 8 - Adding 7 at the end of 4
    // const auto step8 = step4 + step7;

    // 9 - Base58 encoding of 8
    const std::string step8h = fmt::format("{}{}h", step4, step7);
    CryptoPP::Integer step9 { step8h.data() };
    return "1"s + ash::crypto::Base58Encode(step9);
}

std::string GeneratePrivateKey()
{
    CryptoPP::AutoSeededRandomPool prng;
    FieldType::PrivateKey privateKey;
    privateKey.Initialize(prng, CryptoPP::ASN1::secp256k1());

    if (privateKey.Validate(prng, 3))
    {
        std::stringstream ss;
        ss << std::hex << privateKey.GetPrivateExponent();
        return fmt::format("{:0>64}", ss.str());
    }

    return {};
}

} // namespace ash::crypto

} // namespace ash