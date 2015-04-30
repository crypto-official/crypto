// Copyright (c) 2014 bushido
// Copyright (c) 2014 The Vertcoin developers
// Copyright (c) 2014 https://github.com/spesmilo/sx
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STEALTH_H
#define BITCOIN_STEALTH_H

#include <string>
#include <vector>
#include <boost/assign/list_of.hpp>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <array>
#include <utility>
#include <secp256k1.h>

#include "base58.h"
constexpr uint8_t nonce_version = 0x06;
constexpr size_t ec_secret_size = 32;
constexpr size_t ec_compressed_size = 33;
constexpr size_t ec_uncompressed_size = 65;
//template<size_t Size> using byte_array = std::array<uint8_t, Size>;
typedef std::vector<uint8_t> data_chunk;
typedef std::array<uint8_t, ec_secret_size> ec_secret;
typedef data_chunk ec_point;
constexpr uint8_t stealth_version_byte = 0x2a;
constexpr size_t short_hash_size = 20;
constexpr size_t hash_size = 32;
constexpr size_t long_hash_size = 64;

// Standard hash containers.
typedef std::array<uint8_t, short_hash_size> short_hash;
typedef std::array<uint8_t, hash_size> hash_digest;
typedef std::array<uint8_t, long_hash_size> long_hash;

typedef uint32_t stealth_bitfield;


template <typename D, typename T>
void extend_data(D& data, const T& other)
{
    data.insert(std::end(data), std::begin(other), std::end(other));
}

#define VERIFY_UNSIGNED(T) static_assert(std::is_unsigned<T>::value, \
    "The endian functions only work on unsigned types")

template <typename T, typename Iterator>
T from_big_endian(Iterator in)
{
    VERIFY_UNSIGNED(T);
    T out = 0;
    size_t i = sizeof(T);
    while (0 < i)
        out |= static_cast<T>(*in++) << (8 * --i);
    return out;
}

template <typename T, typename Iterator>
T from_little_endian(Iterator in)
{
    VERIFY_UNSIGNED(T);
    T out = 0;
    size_t i = 0;
    while (i < sizeof(T))
        out |= static_cast<T>(*in++) << (8 * i++);
    return out;
}

template <typename T>
std::array<uint8_t, sizeof(T)> to_big_endian(T n)
{
    VERIFY_UNSIGNED(T);
    std::array<uint8_t, sizeof(T)> out;
    for (auto i = out.rbegin(); i != out.rend(); ++i)
    {
        *i = n;
        n >>= 8;
    }
    return out;
}

template <typename T>
std::array<uint8_t, sizeof(T)> to_little_endian(T n)
{
    VERIFY_UNSIGNED(T);
    std::array<uint8_t, sizeof(T)> out;
    for (auto i = out.begin(); i != out.end(); ++i)
    {
        *i = n;
        n >>= 8;
    }
    return out;
}

#undef VERIFY_UNSIGNED

hash_digest bitcoin_hash(const data_chunk& chunk);

uint32_t bitcoin_checksum(const data_chunk& chunk);

void append_checksum(data_chunk& data);

struct stealth_prefix
{
    uint8_t number_bits;
    stealth_bitfield bitfield;
};

struct stealth_address
{
    typedef std::vector<ec_point> pubkey_list;
    enum
    {
        reuse_key_option = 0x01
    };

    bool set_encoded(const std::string& encoded_address);
    std::string encoded() const;

    uint8_t options;
    ec_point scan_pubkey;
    pubkey_list spend_pubkeys;
    size_t number_signatures;
    stealth_prefix prefix;
};


bool verify_checksum(const data_chunk& data);

ec_secret generate_random_secret();


/**
 * Internal class to start and stop the secp256k1 library.
 */
class init_singleton
{
public:
    init_singleton()
      : init_done_(false)
    {}
    ~init_singleton()
    {
        if (init_done_)
            secp256k1_stop();
    }
    void init()
    {
        if (init_done_)
            return;
        secp256k1_start(SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
        init_done_ = true;
    }

private:
    bool init_done_;
};

static init_singleton init;


bool ec_multiply(ec_point& a, const ec_secret& b);
hash_digest sha256_hash(const data_chunk& chunk);

ec_secret shared_secret(const ec_secret& secret, ec_point point);

bool ec_tweak_add(ec_point& a, const ec_secret& b);

ec_point secret_to_public_key(const ec_secret& secret,
    bool compressed);

ec_point initiate_stealth(
    const ec_secret& ephem_secret, const ec_point& scan_pubkey,
    const ec_point& spend_pubkey);

short_hash bitcoin_short_hash(const data_chunk& chunk);

const short_hash null_short_hash = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

class payment_address
{
public:
  enum
     {
         invalid_version = 0xff
     };

   payment_address();
   payment_address(uint8_t version, const short_hash& hash);
   payment_address(const std::string& encoded_address);

   void set(uint8_t version, const short_hash& hash);
   uint8_t version() const;
   const short_hash& hash() const;

   bool set_encoded(const std::string& encoded_address);
   std::string encoded() const;

private:
    uint8_t version_;
    short_hash hash_;
};

void set_public_key(payment_address& address, const data_chunk& public_key);

const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool is_base58(const char c);
bool is_base58(const std::string& text);

ec_point uncover_stealth(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_point& spend_pubkey);

bool ec_add(ec_secret& a, const ec_secret& b);

ec_secret uncover_stealth_secret(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_secret& spend_secret);

std::string secret_to_wif(const ec_secret& secret, bool compressed);

data_chunk decode_hex(std::string hex);

#endif // BITCOIN_STEALTH_H
