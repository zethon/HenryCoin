#pragma once
#include <string_view>

#include <cryptopp/integer.h>

namespace ash
{

namespace crypto
{

std::string SHA256(std::string_view data);

std::string GetPublicKey(std::string_view privateKeyStr);
std::string GetAddressFromPrivateKey(std::string_view privateKeyStr);

} // namespace ash::crypto

} // namespace ash
