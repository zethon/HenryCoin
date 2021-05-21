#pragma once
#include <string_view>

#if _WINDOWS
#pragma warning(push)
#pragma warning(disable:4242)
#endif
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#if _WINDOWS
#pragma warning(pop)
#endif

namespace ash
{

namespace crypto
{

// SHA256 of generic data
std::string SHA256(std::string_view data);
CryptoPP::Integer SHA256Int(std::string_view data);

// given a hex string private key this returns the 
// "04" prepended uncompressed public key
std::string GetPublicKey(std::string_view privateKeyStr);

// give a hex string private key this returns the 
// base58 public address
std::string GetAddressFromPrivateKey(std::string_view privateKeyStr);

// generate a new private key
std::string GeneratePrivateKey();

} // namespace ash::crypto

} // namespace ash
