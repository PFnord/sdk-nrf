/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <assert.h>
#include <stdio.h>
#include <zephyr/kernel.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>

/* Store keys in 2 batches so that some keys can be destroyed between. */
#define FIRST_STORAGE_START PSA_KEY_ID_USER_MIN
#define FIRST_STORAGE_END 2
#define SECOND_STORAGE_START FIRST_STORAGE_END + 1
#define SECOND_STORAGE_END SECOND_STORAGE_START + 100 // More than available slots
#define INCREMENT_ROUNDS 30

/*
Byte index to change to make keys unique.
For RSA keys it is important to not modify DER key meta data.
*/
#define MODIFIED_KEY_BYTE_INDEX 0xF
LOG_MODULE_REGISTER(persistent_key_usage, LOG_LEVEL_DBG);

#define ASSERT_THIS(expr, msg, ...) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "Assertion failed: "); \
	          fprintf(stderr, msg, __VA_ARGS__); \
	          fprintf(stderr, " function %s, file %s, line %d.\n", __func__, __FILE__, __LINE__); \
            assert(expr); \
        } \
    } while (0)

static uint8_t m_input_key[32] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static uint8_t m_output_key[64];

static psa_key_attributes_t                 key_attributes = PSA_KEY_ATTRIBUTES_INIT;

static void setup_test(void)
{

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);

    switch (sizeof(m_input_key))
    {
        // 32 bytes ECC keys (secp256r1)
        case 32:
            psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
            psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(&key_attributes, PSA_BYTES_TO_BITS(32));
            break;
        // 2048 bits RSA private keys are DER-formatted and are very large
        case 1191:
            psa_set_key_algorithm(&key_attributes, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
            psa_set_key_type(&key_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
            psa_set_key_bits(&key_attributes, 2048);
            break;
        default:
            ASSERT_THIS(false, "Unsupported key length: %d", 32);
            break;
    }
}

int main(void)
{
    LOG_DBG("HI");

    psa_status_t         status;
    mbedtls_svc_key_id_t key_id;
    uint32_t             round;
    size_t               out_len;
    uint8_t              stored_key_count[INCREMENT_ROUNDS];
    uint32_t             start_slot   = FIRST_STORAGE_START;
    uint32_t             current_slot = start_slot;

    LOG_DBG("Store and delete keys, increment slot-ids every time buffers are full");

    setup_test();
    for (int j = 0; j <= 20; j++)
    {
        LOG_INF("\nStarting round: %d", j);
        /* First batch of storing */
        for (round = 0; round < INCREMENT_ROUNDS; round++)
        {
            psa_set_key_id(&key_attributes, mbedtls_svc_key_id_make(0, current_slot));
            /* Make all keys unique by changing the first byte to the slot-ID value */
            m_input_key[MODIFIED_KEY_BYTE_INDEX] = current_slot & 0xFF;

            key_id = MBEDTLS_SVC_KEY_ID_INIT;
            LOG_INF("Storing key_id: %d", current_slot);
            status = psa_import_key(&key_attributes, m_input_key, sizeof(m_input_key), &key_id);
            k_sleep(K_MSEC(100));
            if (status == PSA_ERROR_INSUFFICIENT_STORAGE)
            {
                LOG_INF("Storing on slot: %d failed because of insufficient memory", current_slot);
                break;
            }
            current_slot++;
        }
        LOG_DBG("current_sllot %d", current_slot);
        stored_key_count[round] = current_slot - start_slot;
        LOG_DBG("start_sllot %d", start_slot);

        /* Buffers are full, delete all keys so that storing can restart. */
        LOG_INF("Stored %d keys until full, first: %d last: %d", stored_key_count[round],
        start_slot, current_slot - 1);
        /* Export keys */
        for (int d = start_slot; d < current_slot; d++)
        {
            k_sleep(K_MSEC(100));
            LOG_INF("Exporting key_id: %d", d);
            memset(m_output_key, 0x00, sizeof(m_input_key));
            status =
            psa_export_key(mbedtls_svc_key_id_make(0, d), m_output_key, sizeof(m_output_key), &out_len);

            /* Expect stored keys to be unique by changing the first byte, as done when importing.
            */
            m_input_key[MODIFIED_KEY_BYTE_INDEX] = d & 0xFF;
            ASSERT_THIS((status == PSA_SUCCESS), "psa_export_key, key_id: %d", d);
            ASSERT_THIS((out_len == sizeof(m_input_key)), "Export key length check %d", 1);
        }
            /* Clear buffer */
        for (int d = start_slot; d < current_slot; d++)
        {
            k_sleep(K_MSEC(100));
            LOG_INF("Destroying key_id: %d", d);
            status = psa_destroy_key(mbedtls_svc_key_id_make(0, d));
            ASSERT_THIS((status == PSA_SUCCESS), "psa_destroy_key, key_id:%d", d);
        }

        /* We should continue storing on the next value of i */
        LOG_DBG("Will start storing new keys from slot-ID: %d", start_slot);

        /* Start storing on next slot, to make sure that failing slot-id X is not present in flash
         * in the end  */
        start_slot = ++current_slot;
        LOG_DBG("We are at the end");

        /* Verify that all store iterations stored the same number of keys */
    }
    for (round = 0; round < INCREMENT_ROUNDS; round++)
    {
        ASSERT_THIS((stored_key_count[round] == stored_key_count[0]), "Key %d differs from key[0]",
                     round);
    }
}
