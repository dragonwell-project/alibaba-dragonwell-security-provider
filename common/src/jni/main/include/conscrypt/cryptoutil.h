/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONSCRYPT_CRYPTOUTIL_H_
#define CONSCRYPT_CRYPTOUTIL_H_

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evperr.h>
#include <openssl/ocsp.h>

/**
 * Macro defination for crypto and ssl resource release.
 */
typedef STACK_OF(X509) X509_STACK;

// The Enable parameter is ignored and only exists so specializations can use
// SFINAE.
template <typename T, typename Enable = void>
struct DeleterImpl {};

template <typename T>
struct Deleter {
  void operator()(T *ptr) {
    // Rather than specialize Deleter for each type, we specialize
    // DeleterImpl. This allows UniquePtr<T> to be used while only
    // including base.h as long as the destructor is not emitted. This matches
    // std::unique_ptr's behavior on forward-declared types.
    //
    // DeleterImpl itself is specialized in the corresponding module's header
    // and must be included to release an object. If not included, the compiler
    // will error that DeleterImpl<T> does not have a method Free.
    DeleterImpl<T>::Free(ptr);
  }
};

#define MAKE_DELETER(type, deleter)                     \
    template <>                                         \
    struct DeleterImpl<type> {                          \
        static void Free(type *ptr) { deleter(ptr); }   \
    };

// Holds ownership of heap-allocated Tongsuo structures. Sample usage:
//   UniquePtr<RSA> rsa(RSA_new());
//   UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
template <typename T>
using UniquePtr = std::unique_ptr<T, Deleter<T>>;

// This makes a unique_ptr to STACK_OF(type) that owns all elements on the
// stack, i.e. it uses sk_pop_free() to clean up.
#define MAKE_STACK_DELETER(type, deleter)           \
    template <>                                     \
    struct DeleterImpl<STACK_OF(type)> {            \
        static void Free(STACK_OF(type) *ptr) {     \
            sk_##type##_pop_free(ptr, deleter);     \
        }                                           \
    };

MAKE_DELETER(ASN1_OBJECT, ASN1_OBJECT_free)
MAKE_DELETER(ASN1_STRING, ASN1_STRING_free)
MAKE_DELETER(ASN1_TYPE, ASN1_TYPE_free)
MAKE_DELETER(BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free)
MAKE_DELETER(BIGNUM, BN_free)
MAKE_DELETER(BIO, BIO_free)
MAKE_DELETER(BIO_METHOD, BIO_meth_free)
MAKE_DELETER(BN_CTX, BN_CTX_free)
MAKE_DELETER(EC_GROUP, EC_GROUP_free)
MAKE_DELETER(EC_KEY, EC_KEY_free)
MAKE_DELETER(EC_POINT, EC_POINT_free)
MAKE_DELETER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
MAKE_DELETER(EVP_MD_CTX, EVP_MD_CTX_free)
MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
MAKE_DELETER(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
MAKE_DELETER(GENERAL_NAME, GENERAL_NAME_free)
MAKE_DELETER(OCSP_BASICRESP, OCSP_BASICRESP_free)
MAKE_DELETER(OCSP_CERTID, OCSP_CERTID_free)
MAKE_DELETER(OCSP_RESPONSE, OCSP_RESPONSE_free)
MAKE_DELETER(PKCS7, PKCS7_free)
MAKE_DELETER(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free)
MAKE_DELETER(RSA, RSA_free)
MAKE_DELETER(SSL, SSL_free)
MAKE_DELETER(SSL_CTX, SSL_CTX_free)
MAKE_DELETER(uint8_t, OPENSSL_free)
MAKE_DELETER(X509, X509_free)
MAKE_DELETER(X509_NAME, X509_NAME_free)
MAKE_DELETER(X509_CRL, X509_CRL_free)

MAKE_STACK_DELETER(ASN1_OBJECT, ASN1_OBJECT_free)
MAKE_STACK_DELETER(GENERAL_NAME, GENERAL_NAME_free)
MAKE_STACK_DELETER(X509, X509_free)
MAKE_STACK_DELETER(X509_NAME, X509_NAME_free)
MAKE_STACK_DELETER(X509_CRL, X509_CRL_free)

// SSL_SIGN_* are signature algorithm values as defined in TLS 1.3.
#define SSL_SIGN_RSA_PKCS1_SHA1 0x0201
#define SSL_SIGN_RSA_PKCS1_SHA256 0x0401
#define SSL_SIGN_RSA_PKCS1_SHA384 0x0501
#define SSL_SIGN_RSA_PKCS1_SHA512 0x0601
#define SSL_SIGN_ECDSA_SHA1 0x0203
#define SSL_SIGN_ECDSA_SECP256R1_SHA256 0x0403
#define SSL_SIGN_ECDSA_SECP384R1_SHA384 0x0503
#define SSL_SIGN_ECDSA_SECP521R1_SHA512 0x0603
#define SSL_SIGN_RSA_PSS_RSAE_SHA256 0x0804
#define SSL_SIGN_RSA_PSS_RSAE_SHA384 0x0805
#define SSL_SIGN_RSA_PSS_RSAE_SHA512 0x0806
#define SSL_SIGN_ED25519 0x0807
#define SSL_SIGN_SM2_SM3 0x0708

// SSL_SIGN_RSA_PKCS1_MD5_SHA1 is an internal signature algorithm used to
// specify raw RSASSA-PKCS1-v1_5 with an MD5/SHA-1 concatenation, as used in TLS
// before TLS 1.2.
#define SSL_SIGN_RSA_PKCS1_MD5_SHA1 0xff01

typedef struct {
  uint16_t sigalg;
  int pkey_type;
  int curve;
  const EVP_MD *(*digest_func)(void);
  bool is_rsa_pss;
} SSL_SIGNATURE_ALGORITHM;

#endif  // CONSCRYPT_CRYPTOUTIL_H_
