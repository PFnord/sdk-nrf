/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef __CERTIFICATE_H__
#define __CERTIFICATE_H__

typedef struct {
    const unsigned char *ca_certificate;
    const unsigned char *server_certificate;
    const unsigned char *private_key;
    const char *curve;
    int server_certificate_tag;
    int ca_certificate_tag;
    int private_key_tag;
} certificate_info;

#if defined(CONFIG_PSA_TLS_CERTIFICATE_TYPE_RSA)

static const unsigned char ca_certificate[] = {
#include "root-cert.der.inc"
};
static const unsigned char server_certificate[] = {
#include "echo-apps-cert.der.inc"
};
/* This is the private key in pkcs#8 format. */
static const unsigned char private_key[] = {
#include "echo-apps-key.der.inc"
};

#elif defined(CONFIG_PSA_TLS_CERTIFICATE_TYPE_ECDSA)

static const unsigned char ca_certificate_secp256r1[] = {
#include "ec-root-cert_secp256r1.der.inc"
};
static const unsigned char server_certificate_secp256r1[] = {
#include "ec-echo-apps-cert_secp256r1.der.inc"
};
/* This is the private key in pkcs#8 format. */
static const unsigned char private_key_secp256r1[] = {
#include "ec-echo-apps-key_secp256r1.der.inc"
};
static const unsigned char ca_certificate_secp384r1[] = {
#include "ec-root-cert_secp384r1.der.inc"
};
static const unsigned char server_certificate_secp384r1[] = {
#include "ec-echo-apps-cert_secp384r1.der.inc"
};
/* This is the private key in pkcs#8 format. */
static const unsigned char private_key_secp384r1[] = {
#include "ec-echo-apps-key_secp384r1.der.inc"
};

#else

#error "No certificate type selected"

#endif


#endif /* __CERTIFICATE_H__ */
