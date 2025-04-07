/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <nrf.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/tls_credentials.h>
#include "psa_tls_functions.h"
#include "psa_tls_credentials.h"
#include "certificate.h"
#include "dummy_psk.h"
#include "psa/crypto.h"

LOG_MODULE_REGISTER(psa_tls_sample);


static int tls_set_preshared_key(certificate_info cert_info)
{
	LOG_INF("Registering Pre-shared key");

	int err = tls_credential_add(cert_info.private_key_tag, TLS_CREDENTIAL_PSK,
				     psk, sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
		return err;
	}
	err = tls_credential_add(cert_info.private_key_tag, TLS_CREDENTIAL_PSK_ID,
				 psk_id, strlen(psk_id));
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
		return err;
	}

	return APP_SUCCESS;
}


int main(void)
{
	int err;

	LOG_INF("PSA TLS app started");

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	err = psa_crypto_init();
	if (err < 0) {
		return APP_ERROR;
	}
#endif

	certificate_info cert_infos[] = {
	    cert_info_secp256r1,
	    cert_info_secp384r1
	};

	size_t cert_infos_count = sizeof(cert_infos) / sizeof(cert_infos[0]);

	for (size_t i = 0; i < cert_infos_count; i++) {
		err = tls_set_credentials(cert_infos[i]);
		if (err < 0) {
			return APP_ERROR;
		}
		err = tls_set_preshared_key(cert_infos[i]);
		if (err < 0) {
			return APP_ERROR;
		}
		process_psa_tls(cert_infos[i]);
	}


	return APP_SUCCESS;
}
