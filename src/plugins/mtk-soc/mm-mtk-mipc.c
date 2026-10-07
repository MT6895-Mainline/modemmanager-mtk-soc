/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "mm-mtk-mipc.h"

#include <string.h>

#define MIPC_MAGIC 0x24541984u
#define MIPC_VERSION 2

/* Request TLV kinds (subset used by the 0x201 DATA_ACT_CALL_REQ). */
#define MIPC_TLV_APN        0x0101
#define MIPC_TLV_APN_TYPE   0x0102
#define MIPC_TLV_PDP_TYPE   0x0103
#define MIPC_TLV_ROAMING    0x0104
#define MIPC_TLV_AUTH_TYPE  0x0105
#define MIPC_TLV_USERID     0x8106
#define MIPC_TLV_PASSWORD   0x8107
#define MIPC_TLV_IPV4V6_FB  0x0108
#define MIPC_TLV_BEARER     0x0109
#define MIPC_TLV_REUSE_FLAG 0x010a
#define MIPC_TLV_APN_INDEX  0x010c
#define MIPC_TLV_URSP_DESC  0x010d
#define MIPC_TLV_URSP_EVAL  0x010f
/* 0x203 DATA_DEACT_CALL_REQ: tag 0x0101 is the data call id (not the APN) and
 * 0x0102 is MIPC_DEACT_REASON_ENUM. */
#define MIPC_TLV_DEACT_CALL_ID 0x0101
#define MIPC_TLV_DEACT_REASON  0x0102

GQuark
mm_mtk_mipc_error_quark (void)
{
    return g_quark_from_static_string ("mm-mtk-mipc-error");
}

static guint16
read_u16 (const guint8 *p)
{
    return (guint16) p[0] | ((guint16) p[1] << 8);
}

static guint32
read_u32 (const guint8 *p)
{
    return (guint32) p[0] | ((guint32) p[1] << 8) |
           ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

static void
write_u16 (guint8 *p, guint16 value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void
write_u32 (guint8 *p, guint32 value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

void
mm_mtk_mipc_frame_clear (MMMtkMipcFrame *frame)
{
    g_clear_pointer (&frame->payload, g_bytes_unref);
    memset (frame, 0, sizeof (*frame));
}

GBytes *
mm_mtk_mipc_frame_build (guint16       message_id,
                         guint8        ps,
                         guint16       transaction_id,
                         const guint8 *payload,
                         gsize         payload_len)
{
    guint8 *wire;

    g_return_val_if_fail (payload_len <= MM_MTK_MIPC_MAX_PAYLOAD, NULL);
    g_return_val_if_fail (payload_len == 0 || payload != NULL, NULL);

    wire = g_malloc0 (MM_MTK_MIPC_HEADER_SIZE + payload_len);
    write_u32 (wire, MIPC_MAGIC);
    wire[8] = ps;
    write_u16 (wire + 10, message_id);
    write_u16 (wire + 12, transaction_id);
    write_u16 (wire + 14, (guint16) payload_len);
    if (payload_len)
        memcpy (wire + MM_MTK_MIPC_HEADER_SIZE, payload, payload_len);
    return g_bytes_new_take (wire, MM_MTK_MIPC_HEADER_SIZE + payload_len);
}

GBytes *
mm_mtk_mipc_test_request (guint8 ps, guint16 transaction_id)
{
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_TEST_REQ, ps, transaction_id, NULL, 0);
}

static void
append_tlv (GByteArray   *out,
            guint16       kind,
            const guint8 *value,
            guint16       value_len)
{
    guint8 header[4];
    guint8 zeroes[7] = { 0 };
    gsize  block_len = 4 + value_len;
    gsize  padding = (8 - (block_len % 8)) % 8;

    write_u16 (header, kind);
    write_u16 (header + 2, value_len);
    g_byte_array_append (out, header, sizeof (header));
    g_byte_array_append (out, value, value_len);
    if (padding)
        g_byte_array_append (out, zeroes, padding);
}

GBytes *
mm_mtk_mipc_register_ind_request (guint8       ps,
                                  guint16      transaction_id,
                                  guint16      ind_message_id,
                                  GError     **error)
{
    g_autoptr(GByteArray) payload = NULL;
    guint8                buf[2];

    payload = g_byte_array_new ();
    write_u16 (buf, ind_message_id);
    append_tlv (payload, MM_MTK_MIPC_TLV_IND_MSG_ID, buf, sizeof (buf));

    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_REGISTER_IND_REQ, ps,
                                    transaction_id, payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_register_spi_request (guint16 transaction_id)
{
    g_autoptr(GByteArray) payload = g_byte_array_new ();
    guint8 value[2];

    write_u16 (value, MM_MTK_MIPC_SPI_CMD);
    append_tlv (payload, 0x0100, value, sizeof (value));
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_REGISTER_CMD_REQ, 0xff,
                                    transaction_id, payload->data, payload->len);
}

static gboolean
spi_fixed_tlv (GBytes *payload, guint16 kind, guint16 expected,
               const guint8 **value, GError **error)
{
    guint16 length;

    if (!mm_mtk_mipc_find_tlv (payload, kind, value, &length, error))
        return FALSE;
    if (length != expected) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "SPI TLV 0x%04x length %u (expected %u)", kind, length, expected);
        return FALSE;
    }
    return TRUE;
}

gboolean
mm_mtk_mipc_parse_spi_request (const MMMtkMipcFrame *frame,
                             MMMtkMipcSpiRequest *request,
                             GError **error)
{
    MMMtkMipcSpiRequest parsed = { 0 };
    const guint8 *source;
    const guint8 *destination;
    const guint8 *value;

    memset (request, 0, sizeof (*request));
    if (frame->message_id != MM_MTK_MIPC_SPI_CMD || frame->ps != 0xff ||
        !frame->payload) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "Not a global SPI command");
        return FALSE;
    }
    if (!mm_mtk_mipc_find_u32_tlv (frame->payload, 0x0100, &parsed.transaction_id, error) ||
        !mm_mtk_mipc_find_u32_tlv (frame->payload, 0x0101, &parsed.action, error))
        return FALSE;
    if (parsed.action != MM_MTK_MIPC_SPI_ALLOC && parsed.action != MM_MTK_MIPC_SPI_FREE) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "Unsupported SPI action %u", parsed.action);
        return FALSE;
    }
    if (!spi_fixed_tlv (frame->payload, 0x8102, 20, &source, error) ||
        !spi_fixed_tlv (frame->payload, 0x8103, 20, &destination, error) ||
        !spi_fixed_tlv (frame->payload, 0x0104, 1, &value, error))
        return FALSE;
    parsed.protocol = value[0];
    parsed.address_len = read_u32 (source);
    if ((parsed.address_len != 4 && parsed.address_len != 16) ||
        parsed.address_len != read_u32 (destination) ||
        (parsed.protocol != 50 && parsed.protocol != 51)) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "Invalid SPI address family or protocol");
        return FALSE;
    }
    memcpy (parsed.source, source + 4, parsed.address_len);
    memcpy (parsed.destination, destination + 4, parsed.address_len);
    if (parsed.action == MM_MTK_MIPC_SPI_ALLOC) {
        if (!mm_mtk_mipc_find_u32_tlv (frame->payload, 0x0106, &parsed.min_spi, error) ||
            !mm_mtk_mipc_find_u32_tlv (frame->payload, 0x0107, &parsed.max_spi, error) ||
            !spi_fixed_tlv (frame->payload, 0x0105, 1, &value, error))
            return FALSE;
        parsed.mode = value[0];
        if (parsed.mode > 1 || parsed.min_spi < 0x100 || parsed.min_spi > parsed.max_spi) {
            g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                                 "Invalid SPI mode or range");
            return FALSE;
        }
    } else {
        if (!mm_mtk_mipc_find_u32_tlv (frame->payload, 0x8108, &parsed.spi, error))
            return FALSE;
        if (parsed.spi < 0x100) {
            g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                                 "Invalid SPI to release");
            return FALSE;
        }
    }
    *request = parsed;
    return TRUE;
}

GBytes *
mm_mtk_mipc_spi_response (const MMMtkMipcFrame *command,
                         const MMMtkMipcSpiRequest *request,
                         guint32 spi_or_result)
{
    g_autoptr(GByteArray) payload = g_byte_array_new ();
    guint8 value[4];
    guint8 action = (guint8) request->action;

    write_u32 (value, request->transaction_id);
    append_tlv (payload, 0x0100, value, sizeof (value));
    append_tlv (payload, 0x0101, &action, sizeof (action));
    write_u32 (value, spi_or_result);
    append_tlv (payload, 0x8102, value, sizeof (value));
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_SPI_RSP, command->ps,
                                    command->transaction_id, payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_open_request (guint8       ps,
                          guint16      transaction_id,
                          const gchar *client_name,
                          GError     **error)
{
    g_autoptr(GByteArray) payload = NULL;
    guint8               version[4];
    const guint8         usir = 1;
    gsize                name_len;

    if (!client_name || !*client_name ||
        (name_len = strlen (client_name) + 1) > 32) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC client name must fit in 32 bytes");
        return NULL;
    }

    payload = g_byte_array_new ();
    write_u32 (version, MIPC_VERSION);
    append_tlv (payload, 0x0100, version, sizeof (version));
    append_tlv (payload, 0x0101, (const guint8 *) client_name, (guint16) name_len);
    append_tlv (payload, 0x0102, &usir, sizeof (usir));
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_OPEN_REQ, ps, transaction_id,
                                    payload->data, payload->len);
}

/*****************************************************************************/
/* Direct-IP DATA_ACT_CALL_REQ (0x201)                                        */

/* Encodes a C string (including its trailing NUL) as a TLV value. */
static guint8 *
c_string_value (const gchar *str,
                gsize        maximum,
                const gchar *name,
                guint16     *out_len,
                GError     **error)
{
    gsize   len;
    guint8 *value;

    len = strlen (str);
    if (len > maximum) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_OVERSIZED,
                     "MIPC %s exceeds the %" G_GSIZE_FORMAT "-byte field limit",
                     name, maximum);
        return NULL;
    }

    value = g_malloc (len + 1);
    if (len)
        memcpy (value, str, len);
    value[len] = '\0';
    *out_len = (guint16) (len + 1);
    return value;
}

/* The stock writer zeroes the 672-byte struct, copies the DNN and sets
 * protocol_id_next_header (offset 414). */
static void
append_ursp_descriptor (GByteArray  *payload,
                        const gchar *apn)
{
    guint8 *desc;
    gsize   len;

    desc = g_malloc0 (MM_MTK_MIPC_URSP_DESC_SIZE);
    len = strlen (apn);
    desc[1] = (guint8) len;
    if (len)
        memcpy (desc + 4, apn, len);
    desc[414] = 0xff;
    append_tlv (payload, MIPC_TLV_URSP_DESC, desc, MM_MTK_MIPC_URSP_DESC_SIZE);
    g_free (desc);
}

GBytes *
mm_mtk_mipc_ims_pdn_activate_request (guint8 ps, guint16 transaction_id)
{
    g_autoptr(GByteArray) payload = g_byte_array_new ();
    guint8 value[4];

    /* Order matters: the stock frame is written in this sequence. */
    write_u32 (value, 1);
    append_tlv (payload, 0x010f, value, sizeof (value));
    write_u32 (value, 2);
    append_tlv (payload, 0x0102, value, sizeof (value));
    value[0] = 3;
    append_tlv (payload, 0x010a, value, 1);
    append_ursp_descriptor (payload, "ims");

    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_DATA_ACT_REQ, ps, transaction_id,
                                    payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_data_ims_reuse_request (guint8 ps, guint16 transaction_id)
{
    g_autoptr(GByteArray) payload = g_byte_array_new ();
    guint8 value[4];
    guint8 reuse_only = 3;

    /* Same four-TLV hash order as the stock IMS request. */
    write_u32 (value, 0);
    append_tlv (payload, MIPC_TLV_URSP_EVAL, value, sizeof (value));
    write_u32 (value, 2);
    append_tlv (payload, MIPC_TLV_APN_TYPE, value, sizeof (value));
    append_tlv (payload, MIPC_TLV_REUSE_FLAG, &reuse_only, sizeof (reuse_only));
    append_ursp_descriptor (payload, "ims");
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_DATA_ACT_REQ, ps, transaction_id,
                                    payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_data_act_request (guint8        ps,
                              guint16       transaction_id,
                              const gchar  *apn,
                              const gchar  *user,
                              const gchar  *password,
                              GError      **error)
{
    return mm_mtk_mipc_data_act_request_typed (ps, transaction_id, apn, user,
                                               password, 1, 0, error);
}

GBytes *
mm_mtk_mipc_data_act_request_typed (guint8        ps,
                                    guint16       transaction_id,
                                    const gchar  *apn,
                                    const gchar  *user,
                                    const gchar  *password,
                                    guint32       apn_type,
                                    guint32       apn_index,
                                    GError      **error)
{
    g_autoptr(GByteArray) payload = NULL;
    g_autofree guint8 *apn_value = NULL;
    g_autofree guint8 *user_value = NULL;
    g_autofree guint8 *password_value = NULL;
    guint16 apn_len = 0;
    guint16 user_len = 0;
    guint16 password_len = 0;
    guint8  value[4];
    guint8  byte;

    g_return_val_if_fail (error == NULL || *error == NULL, NULL);
    if (!apn) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC APN must be given");
        return NULL;
    }

    apn_value = c_string_value (apn, MM_MTK_MIPC_MAX_APN_LEN, "APN", &apn_len, error);
    if (!apn_value)
        return NULL;
    user_value = c_string_value (user ? user : "", MM_MTK_MIPC_MAX_CREDENTIAL_LEN,
                                 "username", &user_len, error);
    if (!user_value)
        return NULL;
    password_value = c_string_value (password ? password : "",
                                     MM_MTK_MIPC_MAX_CREDENTIAL_LEN,
                                     "password", &password_len, error);
    if (!password_value)
        return NULL;

    payload = g_byte_array_new ();

    /* Stock eight-bucket hash wire order; do not reorder. */
    append_tlv (payload, MIPC_TLV_USERID, user_value, user_len);
    write_u32 (value, 0);
    append_tlv (payload, MIPC_TLV_URSP_EVAL, value, sizeof (value));
    append_tlv (payload, MIPC_TLV_PASSWORD, password_value, password_len);
    byte = 127;
    append_tlv (payload, MIPC_TLV_IPV4V6_FB, &byte, sizeof (byte));
    append_tlv (payload, MIPC_TLV_APN, apn_value, apn_len);
    write_u32 (value, 0x7FFDFFFFu);
    append_tlv (payload, MIPC_TLV_BEARER, value, sizeof (value));
    write_u32 (value, apn_type);
    append_tlv (payload, MIPC_TLV_APN_TYPE, value, sizeof (value));
    byte = 0;
    append_tlv (payload, MIPC_TLV_REUSE_FLAG, &byte, sizeof (byte));
    byte = 3;
    append_tlv (payload, MIPC_TLV_PDP_TYPE, &byte, sizeof (byte));
    write_u32 (value, apn_index);
    append_tlv (payload, MIPC_TLV_APN_INDEX, value, sizeof (value));
    byte = 3;
    append_tlv (payload, MIPC_TLV_ROAMING, &byte, sizeof (byte));
    append_ursp_descriptor (payload, apn);
    /* Auth type: empty credentials in the observed CMCC profile imply 0. */
    byte = 0;
    append_tlv (payload, MIPC_TLV_AUTH_TYPE, &byte, sizeof (byte));

    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_DATA_ACT_REQ, ps, transaction_id,
                                    payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_data_deact_request (guint8    ps,
                                guint16   transaction_id,
                                guint8    call_id,
                                guint8    deact_reason,
                                GError  **error)
{
    g_autoptr(GByteArray) payload = NULL;

    g_return_val_if_fail (error == NULL || *error == NULL, NULL);

    payload = g_byte_array_new ();
    /* Tag 0x0101 means "data call id" here (in 0x201 the same tag is the APN). */
    append_tlv (payload, MIPC_TLV_DEACT_CALL_ID, &call_id, sizeof (call_id));
    append_tlv (payload, MIPC_TLV_DEACT_REASON, &deact_reason, sizeof (deact_reason));
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_DATA_DEACT_REQ, ps, transaction_id,
                                    payload->data, payload->len);
}

GBytes *
mm_mtk_mipc_data_get_call_list_request (guint8  ps,
                                        guint16 transaction_id)
{
    return mm_mtk_mipc_frame_build (MM_MTK_MIPC_DATA_GET_CALL_LIST_REQ, ps,
                                    transaction_id, NULL, 0);
}

/*****************************************************************************/
/* TLV parsing                                                                */

gboolean
mm_mtk_mipc_parse_call_list_cnf (GBytes  *payload,
                                 guint8  *states,
                                 gsize    states_len,
                                 gsize   *n_states,
                                 GError **error)
{
    const guint8 *value = NULL;
    guint16       value_len = 0;
    gsize         copy;

    g_return_val_if_fail (payload != NULL, FALSE);
    g_return_val_if_fail (states != NULL, FALSE);

    if (!mm_mtk_mipc_find_tlv (payload, MM_MTK_MIPC_TLV_CID_LIST, &value, &value_len, error))
        return FALSE;

    copy = MIN ((gsize) value_len, states_len);
    memcpy (states, value, copy);
    if (n_states)
        *n_states = copy;
    return TRUE;
}

gboolean
mm_mtk_mipc_stream_pop (GByteArray     *buffer,
                        MMMtkMipcFrame *frame)
{
    gsize start;
    guint16 payload_len;
    guint8 *data;

    g_return_val_if_fail (buffer != NULL && frame != NULL, FALSE);
    g_return_val_if_fail (frame->payload == NULL, FALSE);

    while (TRUE) {
        /* Keep a possible three-byte split magic while discarding noise. */
        for (start = 0; start + 4 <= buffer->len; start++) {
            if (read_u32 (buffer->data + start) == MIPC_MAGIC)
                break;
        }
        if (start)
            g_byte_array_remove_range (buffer, 0, start);
        if (buffer->len < MM_MTK_MIPC_HEADER_SIZE)
            return FALSE;
        data = buffer->data;
        if (read_u32 (data + 4) == 0 && data[9] == 0)
            break;
        g_byte_array_remove_range (buffer, 0, 1);
    }
    payload_len = read_u16 (data + 14);
    if ((gsize) buffer->len < (gsize) MM_MTK_MIPC_HEADER_SIZE + payload_len)
        return FALSE;

    frame->message_id = read_u16 (data + 10);
    frame->ps = data[8];
    frame->transaction_id = read_u16 (data + 12);
    frame->payload = g_bytes_new (data + MM_MTK_MIPC_HEADER_SIZE, payload_len);
    g_byte_array_remove_range (buffer, 0, MM_MTK_MIPC_HEADER_SIZE + payload_len);
    return TRUE;
}

static gboolean
find_tlv_impl (GBytes        *payload,
               guint16        kind,
               const guint8 **value,
               guint16       *value_len,
               gboolean       required,
               gboolean      *found,
               GError       **error)
{
    gsize         size;
    const guint8 *data;
    gsize         pos = 0;
    gboolean      seen = FALSE;

    g_return_val_if_fail (payload != NULL, FALSE);

    data = g_bytes_get_data (payload, &size);
    while (pos < size) {
        guint16 current_kind;
        guint16 current_len;
        gsize   padded;

        if (size - pos < 4)
            goto truncated;
        current_kind = read_u16 (data + pos);
        current_len = read_u16 (data + pos + 2);
        padded = ((gsize) 4 + current_len + 7) & ~(gsize) 7;
        if (padded > size - pos)
            goto truncated;
        if (current_kind == kind) {
            if (seen) {
                g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                                     MM_MTK_MIPC_ERROR_DUPLICATE,
                                     "Duplicate MIPC TLV");
                return FALSE;
            }
            if (value)
                *value = data + pos + 4;
            if (value_len)
                *value_len = current_len;
            seen = TRUE;
        }
        pos += padded;
    }

    if (found)
        *found = seen;
    if (!seen && required) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC TLV absent");
        return FALSE;
    }
    return TRUE;

truncated:
    g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                         MM_MTK_MIPC_ERROR_TRUNCATED,
                         "Truncated MIPC TLV");
    return FALSE;
}

gboolean
mm_mtk_mipc_find_tlv (GBytes        *payload,
                      guint16        kind,
                      const guint8 **value,
                      guint16       *value_len,
                      GError       **error)
{
    return find_tlv_impl (payload, kind, value, value_len, TRUE, NULL, error);
}

gboolean
mm_mtk_mipc_find_u32_tlv (GBytes   *payload,
                          guint16   kind,
                          guint32  *value,
                          GError  **error)
{
    const guint8 *raw = NULL;
    guint16       len = 0;

    g_return_val_if_fail (value != NULL, FALSE);

    if (!mm_mtk_mipc_find_tlv (payload, kind, &raw, &len, error))
        return FALSE;
    if (len != 4) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "Unexpected MIPC TLV value length");
        return FALSE;
    }
    *value = read_u32 (raw);
    return TRUE;
}

static gboolean
parse_u32 (GBytes   *payload,
           guint16   kind,
           guint32  *value,
           gboolean  required,
           GError  **error)
{
    const guint8 *raw = NULL;
    guint16       len = 0;
    gboolean      found = FALSE;

    if (!find_tlv_impl (payload, kind, &raw, &len, required, &found, error))
        return FALSE;
    if (!found)
        return TRUE;
    if (len != 4) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "Unexpected MIPC TLV value length");
        return FALSE;
    }
    *value = read_u32 (raw);
    return TRUE;
}

static gboolean
parse_u8 (GBytes   *payload,
          guint16   kind,
          guint8   *value,
          GError  **error)
{
    const guint8 *raw = NULL;
    guint16       len = 0;

    if (!mm_mtk_mipc_find_tlv (payload, kind, &raw, &len, error))
        return FALSE;
    if (len != 1) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "Unexpected MIPC TLV value length");
        return FALSE;
    }
    *value = raw[0];
    return TRUE;
}

static gboolean
parse_bytes4 (GBytes   *payload,
              guint16   kind,
              guint8   *value,
              gboolean  required,
              GError  **error)
{
    const guint8 *raw = NULL;
    guint16       len = 0;
    gboolean      found = FALSE;

    if (!find_tlv_impl (payload, kind, &raw, &len, required, &found, error))
        return FALSE;
    if (!found)
        return TRUE;
    if (len != 4) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR,
                             MM_MTK_MIPC_ERROR_INVALID,
                             "Unexpected MIPC TLV value length");
        return FALSE;
    }
    memcpy (value, raw, 4);
    return TRUE;
}

gboolean
mm_mtk_mipc_parse_data_act_cnf (GBytes              *payload,
                                MMMtkMipcDataActCnf *cnf,
                                GError             **error)
{
    g_return_val_if_fail (payload != NULL && cnf != NULL, FALSE);

    memset (cnf, 0, sizeof (*cnf));

    if (!mm_mtk_mipc_find_u32_tlv (payload, MM_MTK_MIPC_TLV_RESULT, &cnf->result, error))
        return FALSE;

    /* Error confirmations only carry the result code. */
    if (cnf->result != 0)
        return TRUE;

    if (!parse_u8 (payload, MM_MTK_MIPC_TLV_DATA_CALL_ID, &cnf->call_id, error))
        return FALSE;
    if (!mm_mtk_mipc_find_u32_tlv (payload, MM_MTK_MIPC_TLV_INTERFACE_ID,
                                   &cnf->interface_id, error))
        return FALSE;
    if (!parse_u32 (payload, MM_MTK_MIPC_TLV_TRANS_INTF_ID, &cnf->trans_intf_id,
                    FALSE, error))
        return FALSE;
    if (!parse_bytes4 (payload, MM_MTK_MIPC_TLV_IPV4_ADDRESS, cnf->ipv4, TRUE, error))
        return FALSE;
    if (!parse_bytes4 (payload, MM_MTK_MIPC_TLV_IPV4_GATEWAY, cnf->gateway, FALSE, error))
        return FALSE;
    if (!mm_mtk_mipc_find_u32_tlv (payload, MM_MTK_MIPC_TLV_IPV4_PREFIX,
                                   &cnf->ipv4_prefix, error))
        return FALSE;
    if (!parse_bytes4 (payload, MM_MTK_MIPC_TLV_DNS1, cnf->dns[0], FALSE, error))
        return FALSE;
    if (!parse_bytes4 (payload, MM_MTK_MIPC_TLV_DNS2, cnf->dns[1], FALSE, error))
        return FALSE;
    if (!parse_u32 (payload, MM_MTK_MIPC_TLV_MTU, &cnf->mtu, FALSE, error))
        return FALSE;
    return TRUE;
}
