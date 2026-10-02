/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "mm-mtk-mipc.h"

#include <stdio.h>
#include <string.h>

/* Expected frames generated with the offline reference encoder
 * docs-local/mtk-soc/mipc_data_candidate.py (DATA_ACT-0x201-CONTRACT.md):
 *
 *   DataActCallCandidate(slot=2, transaction_id=2, apn="cmnet", auth_type=0)
 *   DataActCallCandidate(slot=1, transaction_id=2, apn="internet",
 *                        auth_type=0, username="u", password="p")
 */
static const gchar *expected_cmnet =
    "8419542400000000020001020200100306810100000000000f01040000000000"
    "0781010000000000080101007f00000001010600636d6e657400000000000000"
    "09010400fffffd7f02010400010000000a010100000000000301010003000000"
    "0c0104000000000004010100030000000d01a00200050000636d6e6574000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000ff00000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000501010000000000";

static const gchar *expected_creds =
    "8419542400000000010001020200100306810200750000000f01040000000000"
    "0781020070000000080101007f00000001010900696e7465726e657400000000"
    "09010400fffffd7f02010400010000000a010100000000000301010003000000"
    "0c0104000000000004010100030000000d01a00200080000696e7465726e6574"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000ff00000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000501010000000000";

/* DATA_DEACT_CALL_REQ(ps=2, txid=3, call_id=5, reason=NORMAL):
 * tlv(0x0101, u8 5) + tlv(0x0102, u8 1), both 8-byte aligned. */
static const gchar *expected_deact =
    "84195424000000000200030203001000"
    "01010100050000000201010001000000";

/* DATA_GET_MD_DATA_CALL_LIST_REQ(ps=2, txid=4): empty payload.
 * ps must be the slot: ps=0xff is refused by the modem with result 21. */
static const gchar *expected_call_list_req =
    "841954240000000002000f0204000000";

/* Call-list CNF measured on the device: tlv(0x0000,u32 0) + tlv(0x0100, 50
 * state bytes) where states[i] belongs to cid (i + 1). */
static const gchar *call_list_cnf_payload =
    "0000040000000000000132000100000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000";

/* 0x202 refusal carrying D2CPM_IN_USE. */
static const gchar *cnf_in_use_payload = "00000400d7161400";

/* tlv(0x0000,u32 0) tlv(0x0100,u8 7) tlv(0x0125,u32 3) tlv(0x012a,u32 103)
 * tlv(0x8104,10.20.30.40) tlv(0x8121,10.20.30.1) tlv(0x0128,u32 29)
 * tlv(0x810e,8.8.8.8) tlv(0x810f,1.1.1.1) tlv(0x0123,u32 0) */
static const gchar *cnf_ok_payload =
    "0000040000000000000101000700000025010400030000002a01040067000000"
    "048104000a141e28218104000a141e01280104001d0000000e81040008080808"
    "0f810400010101012301040000000000";

static const gchar *cnf_err_payload = "0000040006000000";

static gchar *
hex_bytes (GBytes *bytes)
{
    g_autoptr(GString) hex = g_string_new (NULL);
    gsize size;
    gsize i;
    const guint8 *data = g_bytes_get_data (bytes, &size);

    for (i = 0; i < size; i++)
        g_string_append_printf (hex, "%02x", data[i]);
    return g_string_free (g_steal_pointer (&hex), FALSE);
}

static GBytes *
bytes_from_hex (const gchar *hex)
{
    gsize         len = strlen (hex);
    gsize         i;
    guint8       *data;

    g_assert_cmpuint (len % 2, ==, 0);
    data = g_malloc (len / 2);
    for (i = 0; i < len / 2; i++) {
        guint value;
        g_assert_true (sscanf (hex + i * 2, "%2x", &value) == 1);
        data[i] = (guint8) value;
    }
    return g_bytes_new_take (data, len / 2);
}

static void
test_stock_wire (void)
{
    g_autoptr(GBytes) test = mm_mtk_mipc_test_request (0xff, 0);
    g_autoptr(GBytes) open = NULL;
    g_autofree gchar *test_hex = hex_bytes (test);
    g_autofree gchar *open_hex = NULL;
    g_autoptr(GError) error = NULL;

    g_assert_cmpstr (test_hex, ==, "8419542400000000ff00050300000000");
    open = mm_mtk_mipc_open_request (0xff, 1, "/dev/ttyCMIPC1", &error);
    g_assert_no_error (error);
    open_hex = hex_bytes (open);
    g_assert_cmpstr (open_hex, ==,
                     "8419542400000000ff000103010028000001040002000000"
                     "01010f002f6465762f747479434d49504331000000000000"
                     "0201010001000000");
}

static void
test_stream_fragments (void)
{
    g_autoptr(GByteArray) buffer = g_byte_array_new ();
    g_autoptr(GBytes) test = mm_mtk_mipc_test_request (0xff, 0);
    g_autoptr(GBytes) open = mm_mtk_mipc_open_request (0xff, 1,
                                                       "/dev/ttyCMIPC1", NULL);
    const guint8 *test_data;
    const guint8 *open_data;
    gsize test_size;
    gsize open_size;
    MMMtkMipcFrame frame = { 0 };
    const guint8 noise[] = { 0, 1, 2 };

    test_data = g_bytes_get_data (test, &test_size);
    open_data = g_bytes_get_data (open, &open_size);
    g_byte_array_append (buffer, noise, sizeof (noise));
    g_byte_array_append (buffer, test_data, 3);
    g_assert_false (mm_mtk_mipc_stream_pop (buffer, &frame));
    g_byte_array_append (buffer, test_data + 3, test_size - 3);
    g_byte_array_append (buffer, open_data, open_size);
    g_assert_true (mm_mtk_mipc_stream_pop (buffer, &frame));
    g_assert_cmpint (frame.message_id, ==, 0x305);
    g_assert_cmpint (frame.ps, ==, 0xff);
    g_assert_cmpint (frame.transaction_id, ==, 0);
    mm_mtk_mipc_frame_clear (&frame);
    g_assert_true (mm_mtk_mipc_stream_pop (buffer, &frame));
    g_assert_cmpint (frame.message_id, ==, 0x301);
    g_assert_cmpint (frame.transaction_id, ==, 1);
    mm_mtk_mipc_frame_clear (&frame);
    g_assert_cmpuint (buffer->len, ==, 0);
}

static void
test_tlv_validation (void)
{
    const guint8 one_result[] = { 0, 0, 4, 0, 21, 0, 0, 0 };
    const guint8 short_result[] = { 0, 0, 4, 0, 21, 0, 0 };
    guint8 duplicate[16];
    g_autoptr(GBytes) payload = NULL;
    g_autoptr(GError) error = NULL;
    guint32 value = 0;

    payload = g_bytes_new_static (one_result, sizeof (one_result));
    g_assert_true (mm_mtk_mipc_find_u32_tlv (payload, 0, &value, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (value, ==, 21);
    g_clear_pointer (&payload, g_bytes_unref);

    payload = g_bytes_new_static (short_result, sizeof (short_result));
    g_assert_false (mm_mtk_mipc_find_u32_tlv (payload, 0, &value, &error));
    g_assert_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_TRUNCATED);
    g_clear_error (&error);
    g_clear_pointer (&payload, g_bytes_unref);

    memcpy (duplicate, one_result, sizeof (one_result));
    memcpy (duplicate + 8, one_result, sizeof (one_result));
    payload = g_bytes_new_static (duplicate, sizeof (duplicate));
    g_assert_false (mm_mtk_mipc_find_u32_tlv (payload, 0, &value, &error));
    g_assert_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_DUPLICATE);
}

static void
test_data_act_frame (void)
{
    g_autoptr(GBytes) frame = NULL;
    g_autofree gchar *hex = NULL;
    g_autoptr(GError) error = NULL;
    gsize size;

    frame = mm_mtk_mipc_data_act_request (2, 2, "cmnet", NULL, NULL, &error);
    g_assert_no_error (error);
    g_assert_nonnull (frame);
    g_bytes_get_data (frame, &size);
    g_assert_cmpuint (size, ==, 800);
    hex = hex_bytes (frame);
    g_assert_cmpstr (hex, ==, expected_cmnet);
    /* The payload itself must be exactly 784 bytes. */
    g_assert_cmpuint (size - MM_MTK_MIPC_HEADER_SIZE, ==, 784);
}

static void
test_data_act_credentials (void)
{
    g_autoptr(GBytes) frame = NULL;
    g_autofree gchar *hex = NULL;
    g_autoptr(GError) error = NULL;

    frame = mm_mtk_mipc_data_act_request (1, 2, "internet", "u", "p", &error);
    g_assert_no_error (error);
    g_assert_nonnull (frame);
    hex = hex_bytes (frame);
    g_assert_cmpstr (hex, ==, expected_creds);
}

static void
test_data_act_oversized_apn (void)
{
    g_autofree gchar *apn = g_strnfill (MM_MTK_MIPC_MAX_APN_LEN + 1, 'a');
    g_autoptr(GBytes) frame = NULL;
    g_autoptr(GError) error = NULL;

    frame = mm_mtk_mipc_data_act_request (1, 2, apn, NULL, NULL, &error);
    g_assert_null (frame);
    g_assert_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_OVERSIZED);
}

static void
test_data_deact_frame (void)
{
    g_autoptr(GBytes) frame = NULL;
    g_autofree gchar *hex = NULL;
    g_autoptr(GError) error = NULL;
    gsize size;

    frame = mm_mtk_mipc_data_deact_request (2, 3, 5,
                                            MM_MTK_MIPC_DEACT_REASON_NORMAL, &error);
    g_assert_no_error (error);
    g_assert_nonnull (frame);
    g_bytes_get_data (frame, &size);
    g_assert_cmpuint (size, ==, 32);
    hex = hex_bytes (frame);
    g_assert_cmpstr (hex, ==, expected_deact);
}

static void
test_call_list_request (void)
{
    g_autoptr(GBytes) frame = NULL;
    g_autofree gchar *hex = NULL;
    gsize size;

    frame = mm_mtk_mipc_data_get_call_list_request (2, 4);
    g_assert_nonnull (frame);
    g_bytes_get_data (frame, &size);
    g_assert_cmpuint (size, ==, MM_MTK_MIPC_HEADER_SIZE);
    hex = hex_bytes (frame);
    g_assert_cmpstr (hex, ==, expected_call_list_req);
}

static void
test_call_list_parse (void)
{
    g_autoptr(GBytes) payload = bytes_from_hex (call_list_cnf_payload);
    guint8 states[MM_MTK_MIPC_CALL_LIST_ENTRIES];
    gsize  n_states = 0;
    g_autoptr(GError) error = NULL;

    memset (states, 0xff, sizeof (states));
    g_assert_true (mm_mtk_mipc_parse_call_list_cnf (payload, states, sizeof (states),
                                                    &n_states, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (n_states, ==, MM_MTK_MIPC_CALL_LIST_ENTRIES);
    g_assert_cmpuint (states[0], ==, 1);   /* cid 1 is active */
    g_assert_cmpuint (states[1], ==, 0);
}

static void
test_in_use_result (void)
{
    g_autoptr(GBytes) payload = bytes_from_hex (cnf_in_use_payload);
    MMMtkMipcDataActCnf cnf;
    g_autoptr(GError) error = NULL;

    g_assert_true (mm_mtk_mipc_parse_data_act_cnf (payload, &cnf, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (cnf.result, ==, MM_MTK_MIPC_RESULT_D2CPM_IN_USE);
    g_assert_cmpuint (cnf.call_id, ==, 0);
}

static void
test_ims_reuse_frame (void)
{
    g_autoptr(GBytes) request = mm_mtk_mipc_data_ims_reuse_request (2, 0x05fc);
    g_autoptr(GBytes) prefix = bytes_from_hex (
        "841954240000000002000102fc05c002"
        "0f0104000000000002010400020000000a010100030000000d01a002");
    g_autoptr(GByteArray) buffer = g_byte_array_new ();
    MMMtkMipcFrame frame = { 0 };
    const guint8 *data;
    const guint8 *value;
    guint16 length;
    gsize size;
    gsize prefix_size;
    const guint8 *prefix_data;
    guint8 descriptor[MM_MTK_MIPC_URSP_DESC_SIZE] = { 0 };

    data = g_bytes_get_data (request, &size);
    prefix_data = g_bytes_get_data (prefix, &prefix_size);
    g_assert_cmpuint (size, ==, 720);
    g_assert_cmpmem (data, prefix_size, prefix_data, prefix_size);
    g_byte_array_append (buffer, data, size);
    g_assert_true (mm_mtk_mipc_stream_pop (buffer, &frame));
    g_assert_cmpuint (g_bytes_get_size (frame.payload), ==, 704);
    g_assert_true (mm_mtk_mipc_find_tlv (frame.payload, 0x010d, &value, &length, NULL));
    descriptor[1] = 3;
    memcpy (descriptor + 4, "ims", 3);
    descriptor[414] = 0xff;
    g_assert_cmpuint (length, ==, sizeof (descriptor));
    g_assert_cmpmem (value, length, descriptor, sizeof (descriptor));
    g_assert_false (mm_mtk_mipc_find_tlv (frame.payload, 0x0101, &value, &length, NULL));
    mm_mtk_mipc_frame_clear (&frame);
}

static void
test_data_act_cnf_parse (void)
{
    g_autoptr(GBytes) payload = bytes_from_hex (cnf_ok_payload);
    MMMtkMipcDataActCnf cnf;
    g_autoptr(GError) error = NULL;

    g_assert_true (mm_mtk_mipc_parse_data_act_cnf (payload, &cnf, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (cnf.result, ==, 0);
    g_assert_cmpuint (cnf.call_id, ==, 7);
    g_assert_cmpuint (cnf.interface_id, ==, 3);
    g_assert_cmpuint (cnf.trans_intf_id, ==, 103);
    g_assert_cmpuint (cnf.ipv4[0], ==, 10);
    g_assert_cmpuint (cnf.ipv4[1], ==, 20);
    g_assert_cmpuint (cnf.ipv4[2], ==, 30);
    g_assert_cmpuint (cnf.ipv4[3], ==, 40);
    g_assert_cmpuint (cnf.gateway[0], ==, 10);
    g_assert_cmpuint (cnf.gateway[3], ==, 1);
    g_assert_cmpuint (cnf.ipv4_prefix, ==, 29);
    g_assert_cmpuint (cnf.dns[0][0], ==, 8);
    g_assert_cmpuint (cnf.dns[1][3], ==, 1);
    g_assert_cmpuint (cnf.mtu, ==, 0);
    /* Cross-check the ccmni index derivation used by the bearer. */
    g_assert_cmpuint (cnf.interface_id, ==, cnf.trans_intf_id % 100);
}

static void
test_data_act_cnf_error (void)
{
    g_autoptr(GBytes) payload = bytes_from_hex (cnf_err_payload);
    MMMtkMipcDataActCnf cnf;
    g_autoptr(GError) error = NULL;

    g_assert_true (mm_mtk_mipc_parse_data_act_cnf (payload, &cnf, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (cnf.result, ==, 6);
    g_assert_cmpuint (cnf.call_id, ==, 0);
    g_assert_cmpuint (cnf.interface_id, ==, 0);
    g_assert_cmpuint (cnf.ipv4_prefix, ==, 0);
}

static const gchar *spi_alloc_payload =
    "00010400214365870101040000000000"
    "060104000001000007010400ffffff0f"
    "028114000400000000000000000000000000000000000000"
    "03811400040000000a14283c000000000000000000000000"
    "04010100320000000501010000000000";

static const gchar *spi_free_payload =
    "00010400224365870101040001000000"
    "0881040078563412"
    "028114001000000000000000000000000000000000000000"
    "038114001000000020010db8000000000000000000000001"
    "0401010032000000";

static void
test_spi_register (void)
{
    g_autoptr(GBytes) wire = mm_mtk_mipc_register_spi_request (0x70);
    g_autofree gchar *hex = hex_bytes (wire);

    g_assert_cmpstr (hex, ==,
                     "8419542400000000ff000b03700008000001020005830000");
}

static void
test_spi_alloc (void)
{
    MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 0x1234, NULL };
    MMMtkMipcSpiRequest request;
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) response = NULL;
    g_autofree gchar *hex = NULL;

    frame.payload = bytes_from_hex (spi_alloc_payload);
    g_assert_true (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (request.transaction_id, ==, 0x87654321);
    g_assert_cmpuint (request.action, ==, MM_MTK_MIPC_SPI_ALLOC);
    g_assert_cmpuint (request.address_len, ==, 4);
    g_assert_cmpuint (request.min_spi, ==, 256);
    g_assert_cmpuint (request.max_spi, ==, 0x0fffffff);
    g_assert_cmpuint (request.protocol, ==, 50);
    g_assert_cmpuint (request.mode, ==, 0);
    g_assert_cmpmem (request.destination, 4, "\x0a\x14\x28\x3c", 4);
    response = mm_mtk_mipc_spi_response (&frame, &request, 0x12345678);
    hex = hex_bytes (response);
    g_assert_cmpstr (hex, ==,
                     "8419542400000000ff00068334121800"
                     "000104002143658701010100000000000281040078563412");
    mm_mtk_mipc_frame_clear (&frame);
}

static void
test_spi_free (void)
{
    MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 0x4321, NULL };
    MMMtkMipcSpiRequest request;
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) response = NULL;
    g_autofree gchar *hex = NULL;

    frame.payload = bytes_from_hex (spi_free_payload);
    g_assert_true (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (request.action, ==, MM_MTK_MIPC_SPI_FREE);
    g_assert_cmpuint (request.address_len, ==, 16);
    g_assert_cmpuint (request.spi, ==, 0x12345678);
    g_assert_cmpuint (request.destination[15], ==, 1);
    response = mm_mtk_mipc_spi_response (&frame, &request, 1);
    hex = hex_bytes (response);
    g_assert_cmpstr (hex, ==,
                     "8419542400000000ff00068321431800"
                     "000104002243658701010100010000000281040001000000");
    mm_mtk_mipc_frame_clear (&frame);
}

static void
test_spi_alloc_ipv6 (void)
{
    MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 2, NULL };
    MMMtkMipcSpiRequest request;
    g_autoptr(GBytes) original = bytes_from_hex (spi_alloc_payload);
    g_autoptr(GBytes) response = NULL;
    g_autoptr(GError) error = NULL;
    g_autofree gchar *hex = NULL;
    gsize size;
    const guint8 *data = g_bytes_get_data (original, &size);
    guint8 *copy = g_memdup2 (data, size);

    copy[36] = copy[60] = 16;
    memset (copy + 64, 0, 16);
    memcpy (copy + 64, "\x20\x01\x0d\xb8", 4);
    copy[79] = 1;
    frame.payload = g_bytes_new_take (copy, size);
    g_assert_true (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (request.address_len, ==, 16);
    g_assert_cmpuint (request.destination[15], ==, 1);
    response = mm_mtk_mipc_spi_response (&frame, &request, 0);
    hex = hex_bytes (response);
    g_assert_cmpstr (hex, ==,
                     "8419542400000000ff00068302001800"
                     "000104002143658701010100000000000281040000000000");
    mm_mtk_mipc_frame_clear (&frame);
}

static void
test_spi_invalid (void)
{
    static const struct {
        gsize offset;
        guint8 value;
    } invalid[] = {
        { 10, 1 }, /* action incorrectly encoded as u8 */
        { 12, 2 }, /* unsupported action */
        { 21, 0 }, /* SPI range starts below 256 */
        { 28, 0 }, /* reversed range when max=0 */
        { 34, 16 }, /* address structure too short */
        { 36, 5 }, /* invalid address size */
        { 60, 16 }, /* inconsistent address families */
        { 84, 6 }, /* TCP is not an IPsec SPI protocol */
        { 92, 2 }, /* unsupported mode */
    };
    g_autoptr(GBytes) original = bytes_from_hex (spi_alloc_payload);
    const guint8 *data;
    gsize size;
    guint i;

    data = g_bytes_get_data (original, &size);
    for (i = 0; i < G_N_ELEMENTS (invalid); i++) {
        MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 1, NULL };
        MMMtkMipcSpiRequest request;
        g_autoptr(GError) error = NULL;
        guint8 *copy = g_memdup2 (data, size);

        if (i == 3)
            memset (copy + 28, 0, 4);
        else
            copy[invalid[i].offset] = invalid[i].value;
        frame.payload = g_bytes_new_take (copy, size);
        g_assert_false (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
        g_assert_nonnull (error);
        g_assert_cmpuint (request.transaction_id, ==, 0);
        mm_mtk_mipc_frame_clear (&frame);
    }
    for (i = 0; i < size; i++) {
        MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 1, NULL };
        MMMtkMipcSpiRequest request;
        g_autoptr(GError) error = NULL;

        frame.payload = g_bytes_new (data, i);
        g_assert_false (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
        g_assert_nonnull (error);
        mm_mtk_mipc_frame_clear (&frame);
    }
    {
        MMMtkMipcFrame frame = { MM_MTK_MIPC_SPI_CMD, 0xff, 1, NULL };
        MMMtkMipcSpiRequest request;
        g_autoptr(GError) error = NULL;
        g_autoptr(GByteArray) duplicated = g_byte_array_new ();

        g_byte_array_append (duplicated, data, size);
        g_byte_array_append (duplicated, data, 8);
        frame.payload = g_bytes_new (duplicated->data, duplicated->len);
        g_assert_false (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
        g_assert_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_DUPLICATE);
        g_clear_error (&error);
        g_clear_pointer (&frame.payload, g_bytes_unref);
        frame.payload = g_bytes_ref (original);
        frame.ps = 1;
        g_assert_false (mm_mtk_mipc_parse_spi_request (&frame, &request, &error));
        g_assert_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID);
        mm_mtk_mipc_frame_clear (&frame);
    }
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    g_test_add_func ("/mipc/stock-wire", test_stock_wire);
    g_test_add_func ("/mipc/stream-fragments", test_stream_fragments);
    g_test_add_func ("/mipc/tlv-validation", test_tlv_validation);
    g_test_add_func ("/mipc/data-act-frame", test_data_act_frame);
    g_test_add_func ("/mipc/data-act-credentials", test_data_act_credentials);
    g_test_add_func ("/mipc/data-act-oversized-apn", test_data_act_oversized_apn);
    g_test_add_func ("/mipc/data-deact-frame", test_data_deact_frame);
    g_test_add_func ("/mipc/call-list-request", test_call_list_request);
    g_test_add_func ("/mipc/call-list-parse", test_call_list_parse);
    g_test_add_func ("/mipc/d2cpm-in-use-result", test_in_use_result);
    g_test_add_func ("/mipc/data-act-cnf-parse", test_data_act_cnf_parse);
    g_test_add_func ("/mipc/ims-reuse-frame", test_ims_reuse_frame);
    g_test_add_func ("/mipc/data-act-cnf-error", test_data_act_cnf_error);
    g_test_add_func ("/mipc/spi-register", test_spi_register);
    g_test_add_func ("/mipc/spi-alloc", test_spi_alloc);
    g_test_add_func ("/mipc/spi-free", test_spi_free);
    g_test_add_func ("/mipc/spi-alloc-ipv6", test_spi_alloc_ipv6);
    g_test_add_func ("/mipc/spi-invalid", test_spi_invalid);
    return g_test_run ();
}
