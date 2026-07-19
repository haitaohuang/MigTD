/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _CRYPTO_WRAPPER_H
#define _CRYPTO_WRAPPER_H

#include <openssl/evp.h>
#include "sgx_report.h"
#include "sgx_error.h"

#define SIGNATURE_SIZE 384

#ifdef  __cplusplus
extern "C" {
#endif

sgx_status_t sgx_EVP_Digest(const EVP_MD *type, const uint8_t *p_src, unsigned int src_len, uint8_t *digest, unsigned int *digest_len);
sgx_status_t sgx_cmac128_msg(const sgx_key_128bit_t key, const uint8_t *p_src, unsigned int src_len, sgx_mac_t *p_mac);
void *create_rsa_key_pair(int n_byte_size, uint32_t e);
void *create_rsa_pub_key(const unsigned char *p_n, int len_n, const unsigned char *p_e, int len_e);
bool get_rsa_pub_key(void *pkey, uint8_t *p_n, uint8_t *p_e);
void free_rsa_key(void *pkey);
bool create_rsa3072_signature(void *pkey, const uint8_t *p_data, uint32_t data_size, uint8_t *p_signature, size_t siglen);
bool verify_rsa3072_signature(void *pkey, const uint8_t *p_data, uint32_t data_size, uint8_t *p_signature, size_t siglen);

#ifdef  __cplusplus
}
#endif

#endif

