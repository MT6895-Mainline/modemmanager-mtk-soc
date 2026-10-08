/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * MediaTek CCCI direct-IP bearer.
 *
 * The connection is not AT based: it opens the MIPC control channel
 * (/dev/ttyCMIPC1), runs the TEST/OPEN handshake and issues a
 * DATA_ACT_CALL_REQ per candidate SIM slot.  The confirmation carries the
 * static IPv4 configuration and the ccmni interface index, which is used to
 * pick the data port reported to ModemManager.  All of the blocking I/O runs
 * in a GTask worker thread with poll() deadlines.
 */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <glib-unix.h>

#include "ModemManager.h"
#include "mm-broadband-bearer-mtk-soc.h"
#include "mm-broadband-modem-mtk-soc.h"
#include "mm-log-object.h"
#include "mm-mtk-mipc.h"
#include "mm-mtk-ipsec.h"

#define MIPC_PORT              "/dev/ttyCMIPC1"
#define MIPC_CLIENT_NAME       "/dev/ttyCMIPC1"
#define MIPC_TXID_TEST         0
#define MIPC_TXID_OPEN         1
#define MIPC_TXID_DATA_ACT     2
#define MIPC_TXID_DATA_DEACT   3
#define MIPC_TXID_CALL_LIST    4
/* Separate transaction for the IMS bearer so it can never be confused with
 * the default-data one. */
#define MIPC_TXID_IMS_ACT           0x00e0
#define MIPC_TXID_IMS_RETRY_TIMER   0x00df
#define MIPC_TXID_DATA_ACT_RETRY 5
#define MIPC_TXID_REGIND       16
#define MIPC_TEST_TIMEOUT_MS   3000
#define MIPC_OPEN_TIMEOUT_MS   3000
#define MIPC_DATA_TIMEOUT_MS   15000
#define MIPC_DEACT_TIMEOUT_MS  3000
#define MIPC_DEFAULT_MTU       1410
#define MIPC_MAX_SLOT_ATTEMPTS 2
#define MIPC_IND_LOG_BYTES      64
#define MIPC_IND_DIAG_LOG_BYTES 192
#define MIPC_IND_DATA_LOG_BYTES 512
#define MIPC_TXID_REGSPI       0x70
#define MIPC_TXID_CLOSE        0x72

struct _MMBroadbandBearerMtkSocPrivate {
    /* Kept open while the data call is up, so disconnect can send DATA_DEACT. */
    gint        fd;
    guint8      slot;
    GMutex      mutex;
    /* Poll callbacks drain INDs on the baseline path. The optional SPI service
     * also uses fd readiness because the modem's allocation deadline is 5s.
     * Both readers share this mutex and buffer; disconnect removes the sources
     * before handing the fd to its worker. */
    GByteArray *ind_buffer;
    MMMtkIpsec *ipsec;
    guint       mipc_source;
    guint       ipsec_source;
    guint       spi_timeout;
    gboolean    spi_requested;
    gboolean    spi_owned;
};

static MMPort *mtk_soc_net_port (MMBroadbandModem *modem,
                                 guint32           interface_id);

G_DEFINE_TYPE_WITH_PRIVATE (MMBroadbandBearerMtkSoc, mm_broadband_bearer_mtk_soc, MM_TYPE_BROADBAND_BEARER)

static void mipc_spi_start (MMBroadbandBearerMtkSoc *self);

/*****************************************************************************/
/* Blocking MIPC I/O helpers                                                  */

static gchar *
ipv4_to_string (const guint8 *address)
{
    return g_strdup_printf ("%u.%u.%u.%u",
                            address[0], address[1], address[2], address[3]);
}

static gboolean
mipc_write_all (gint      fd,
                GBytes   *bytes,
                GError  **error)
{
    const guint8 *data;
    gsize         size;
    gsize         offset = 0;

    data = g_bytes_get_data (bytes, &size);
    while (offset < size) {
        ssize_t written;

        written = write (fd, data + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN) {
                struct pollfd pfd;
                gint          ready;

                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                ready = poll (&pfd, 1, 1000);
                if (ready > 0 || (ready < 0 && errno == EINTR))
                    continue;
                g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_TRUNCATED,
                             "Timed out writing to %s", MIPC_PORT);
                return FALSE;
            }
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "Couldn't write to %s: %s", MIPC_PORT, g_strerror (errno));
            return FALSE;
        }
        if (written == 0) {
            g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                                 "Short write to MIPC port");
            return FALSE;
        }
        offset += (gsize) written;
    }
    return TRUE;
}

/* qqcandy: the modem only sends us unsolicited messages (INDs) for the ids we
 * subscribed to with MM_MTK_MIPC_REGISTER_IND_REQ -- and until now every frame
 * that was not the CNF we happened to be waiting for was silently dropped, which
 * is why the firmware's own reporting (IMS state/VoPS/registration, network
 * registration, SIM events) was invisible.  Log them instead of discarding. */
/* qqcandy: 0x4302 INTERNAL_EIF_IND carries the interface up/down report.  The
 * stock RILD turns it into "+EIF: <id>, ifup, <type>, <ipv4>, <ipv6>, <n>" and
 * then configures the matching ccmni interface.  Nothing in our stack did that,
 * which is why the IMS PDN could be active inside the modem while the host side
 * never got an interface.  Walk the TLVs and log them; the interface id is
 * TLV 0x0401 (u32). */
static void
mm_mtk_eif_decode (const guint8 *data, gsize size)
{
    gsize off = 0;

    while (off + 4 <= size) {
        guint16 kind = (guint16) (data[off] | (data[off + 1] << 8));
        guint16 len  = (guint16) (data[off + 2] | (data[off + 3] << 8));
        gsize   voff = off + 4;
        gsize   block;

        if (voff + len > size)
            break;
        block = 4 + len;
        block = (block + 7) & ~(gsize) 7;   /* TLVs are padded to 8 bytes */

        if (len == 4) {
            guint32 v = (guint32) data[voff] | ((guint32) data[voff + 1] << 8) |
                        ((guint32) data[voff + 2] << 16) | ((guint32) data[voff + 3] << 24);
            g_debug ("mtk-soc: EIF tlv 0x%04x u32=%u (0x%x)", kind, v, v);
        } else if (len >= 4 && len <= 16) {
            g_autofree gchar *hex = g_malloc (len * 2 + 1);
            gsize i;
            for (i = 0; i < len; i++)
                g_snprintf (hex + i * 2, 3, "%02x", data[voff + i]);
            g_debug ("mtk-soc: EIF tlv 0x%04x len=%u hex=%s", kind, len, hex);
        } else {
            g_debug ("mtk-soc: EIF tlv 0x%04x len=%u", kind, len);
        }

        off += block;
        if (block == 0)
            break;
    }
}

static void
mipc_handle_unsolicited (const MMMtkMipcFrame *frame)
{
    const guint8 *data = NULL;
    gsize         size = 0;
    gchar         hex[MIPC_IND_DATA_LOG_BYTES * 2 + 1];
    gsize         i;
    gsize         n;
    gsize         limit = MIPC_IND_LOG_BYTES;

    if (frame->payload)
        data = g_bytes_get_data (frame->payload, &size);

    if (g_strcmp0 (g_getenv ("QQC_MIPC_IMS_DIAGNOSTICS"), "1") == 0) {
        if (frame->message_id == 0x4401 || frame->message_id == 0x4a06)
            limit = MIPC_IND_DIAG_LOG_BYTES;
        else if (frame->message_id == 0x4201 || frame->message_id == 0x420a ||
                 frame->message_id == 0x420f || frame->message_id == 0x4218)
            limit = MIPC_IND_DATA_LOG_BYTES;
    }
    n = MIN (size, limit);
    for (i = 0; i < n; i++)
        g_snprintf (hex + i * 2, 3, "%02x", data[i]);
    hex[n * 2] = '\0';

    g_debug ("mtk-soc: modem IND 0x%04x ps=%u txid=0x%04x len=%u%s%s%s",
             frame->message_id, frame->ps, frame->transaction_id,
             (guint) size, size ? " " : "", hex,
             n < size ? " [truncated]" : "");

    if (frame->message_id == 0x4302 && data && size)
        mm_mtk_eif_decode (data, size);
}

static gboolean
mipc_handle_spi (MMBroadbandBearerMtkSocPrivate *priv, const MMMtkMipcFrame *frame)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) response = NULL;
    MMMtkMipcSpiRequest request;
    guint32 result;

    if (!priv->ipsec)
        return FALSE;
    if (frame->message_id == MM_MTK_MIPC_REGISTER_CMD_CNF &&
        frame->ps == 0xff && frame->transaction_id == MIPC_TXID_REGSPI &&
        priv->spi_requested) {
        if (!mm_mtk_mipc_find_u32_tlv (frame->payload, MM_MTK_MIPC_TLV_RESULT, &result, &error)) {
            g_warning ("mtk-soc: SPI registration invalid: %s", error->message);
            return TRUE;
        }
        priv->spi_requested = FALSE;
        priv->spi_owned = (result == 0);
        if (priv->spi_timeout) {
            g_source_remove (priv->spi_timeout);
            priv->spi_timeout = 0;
        }
        g_message ("mtk-soc: SPI command registration result=%u owned=%u", result, priv->spi_owned);
        return TRUE;
    }
    if (frame->message_id != MM_MTK_MIPC_SPI_CMD)
        return FALSE;
    if (!priv->spi_owned) {
        g_warning ("mtk-soc: SPI command received without confirmed ownership");
        return TRUE;
    }
    if (!mm_mtk_mipc_parse_spi_request (frame, &request, &error)) {
        g_warning ("mtk-soc: invalid SPI command: %s", error->message);
        return TRUE;
    }
    if (request.action == MM_MTK_MIPC_SPI_ALLOC)
        result = mm_mtk_ipsec_allocate (priv->ipsec, &request, &error);
    else
        result = mm_mtk_ipsec_release (priv->ipsec, &request, &error) ? 1 : 0;
    g_message ("mtk-soc: SPI command tx=%u frame_tx=%u action=%u IPv%u proto=%u result=%u%s%s",
               request.transaction_id, frame->transaction_id, request.action,
               request.address_len == 4 ? 4 : 6, request.protocol, result,
               error ? " error=" : "", error ? error->message : "");
    g_clear_error (&error);
    response = mm_mtk_mipc_spi_response (frame, &request, result);
    if (!mipc_write_all (priv->fd, response, &error))
        g_warning ("mtk-soc: SPI response write failed: %s", error->message);
    return TRUE;
}

/* Pick up anything the modem queued for us.  The caller must hold priv->mutex
 * and must have checked priv->fd >= 0.  Non-blocking and best effort: a partial
 * frame simply stays in ind_buffer until the rest arrives. */
static void
mipc_drain_unsolicited (MMBroadbandBearerMtkSocPrivate *priv)
{
    MMMtkMipcFrame frame = { 0 };
    guint8         chunk[4096];
    gssize         n;

    for (;;) {
        n = read (priv->fd, chunk, sizeof (chunk));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        g_byte_array_append (priv->ind_buffer, chunk, (guint) n);
    }

    while (mm_mtk_mipc_stream_pop (priv->ind_buffer, &frame)) {
        if (!mipc_handle_spi (priv, &frame))
            mipc_handle_unsolicited (&frame);
        mm_mtk_mipc_frame_clear (&frame);
    }
}

static gboolean
mipc_readable (gint fd, GIOCondition condition, gpointer user_data)
{
    MMBroadbandBearerMtkSocPrivate *priv;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (user_data);
    g_mutex_lock (&priv->mutex);
    if (priv->fd != fd || (condition & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))) {
        priv->mipc_source = 0;
        g_mutex_unlock (&priv->mutex);
        g_warning ("mtk-soc: SPI MIPC reader stopped (condition=%u)", condition);
        return G_SOURCE_REMOVE;
    }
    mipc_drain_unsolicited (priv);
    g_mutex_unlock (&priv->mutex);
    return G_SOURCE_CONTINUE;
}

static gboolean
ipsec_readable (gint fd, GIOCondition condition, gpointer user_data)
{
    MMBroadbandBearerMtkSocPrivate *priv;
    g_autoptr(GError) error = NULL;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (user_data);
    g_mutex_lock (&priv->mutex);
    if (!priv->ipsec || mm_mtk_ipsec_fd (priv->ipsec) != fd ||
        (condition & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))) {
        priv->ipsec_source = 0;
        g_mutex_unlock (&priv->mutex);
        g_warning ("mtk-soc: SPI expiry reader stopped (condition=%u)", condition);
        return G_SOURCE_REMOVE;
    }
    if (!mm_mtk_ipsec_renew (priv->ipsec, &error))
        g_warning ("mtk-soc: SPI renewal failed: %s", error->message);
    g_mutex_unlock (&priv->mutex);
    return G_SOURCE_CONTINUE;
}

static gboolean
spi_registration_timeout (gpointer user_data)
{
    MMBroadbandBearerMtkSocPrivate *priv;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (user_data);
    g_mutex_lock (&priv->mutex);
    priv->spi_timeout = 0;
    if (priv->spi_requested)
        g_warning ("mtk-soc: SPI registration has no CNF; no retry or blind unregister");
    g_mutex_unlock (&priv->mutex);
    return G_SOURCE_REMOVE;
}

static void
mipc_spi_stop_sources (MMBroadbandBearerMtkSocPrivate *priv)
{
    if (priv->mipc_source)
        g_source_remove (priv->mipc_source);
    if (priv->ipsec_source)
        g_source_remove (priv->ipsec_source);
    if (priv->spi_timeout)
        g_source_remove (priv->spi_timeout);
    priv->mipc_source = priv->ipsec_source = priv->spi_timeout = 0;
    priv->spi_owned = priv->spi_requested = FALSE;
}

static void
mipc_spi_close_client (gint fd)
{
    g_autoptr(GBytes) close_request = NULL;
    g_autoptr(GError) error = NULL;

    /* CLOSE only removes this client's owners. UNREGISTER_CMD can remove any
     * client's owner and is unsafe after a lost/refused registration reply. */
    close_request = mm_mtk_mipc_frame_build (MM_MTK_MIPC_CLOSE_REQ, 0xff,
                                            MIPC_TXID_CLOSE, NULL, 0);
    if (!mipc_write_all (fd, close_request, &error))
        g_warning ("mtk-soc: SPI client close failed: %s", error->message);
}

static void
mipc_spi_start (MMBroadbandBearerMtkSoc *self)
{
    MMBroadbandBearerMtkSocPrivate *priv;
    g_autoptr(GError) error = NULL;
    g_autoptr(GBytes) registration = NULL;

    if (g_strcmp0 (g_getenv ("QQC_MIPC_SPI_SERVICE"), "1") != 0)
        return;
    priv = mm_broadband_bearer_mtk_soc_get_instance_private (self);
    g_mutex_lock (&priv->mutex);
    priv->ipsec = mm_mtk_ipsec_new (&error);
    if (!priv->ipsec) {
        g_warning ("mtk-soc: SPI service unavailable: %s", error->message);
        g_mutex_unlock (&priv->mutex);
        return;
    }
    priv->mipc_source = g_unix_fd_add (priv->fd, G_IO_IN | G_IO_ERR | G_IO_HUP,
                                      mipc_readable, self);
    priv->ipsec_source = g_unix_fd_add (mm_mtk_ipsec_fd (priv->ipsec),
                                       G_IO_IN | G_IO_ERR | G_IO_HUP, ipsec_readable, self);
    priv->spi_requested = TRUE;
    priv->spi_timeout = g_timeout_add (MIPC_TEST_TIMEOUT_MS, spi_registration_timeout, self);
    registration = mm_mtk_mipc_register_spi_request (MIPC_TXID_REGSPI);
    if (!mipc_write_all (priv->fd, registration, &error))
        g_warning ("mtk-soc: SPI registration write failed: %s", error->message);
    g_mutex_unlock (&priv->mutex);
}

static gboolean
mipc_wait_frame (gint             fd,
                 GByteArray      *buffer,
                 guint16          message_id,
                 guint8           ps,
                 guint16          transaction_id,
                 guint            timeout_ms,
                 MMMtkMipcFrame  *frame,
                 GError         **error)
{
    gint64 deadline;

    deadline = g_get_monotonic_time () + ((gint64) timeout_ms) * 1000;
    while (TRUE) {
        gint64        now;
        gint          remaining;
        struct pollfd pfd;
        guint8        chunk[4096];
        ssize_t       n;

        while (mm_mtk_mipc_stream_pop (buffer, frame)) {
            if (frame->message_id == message_id &&
                frame->ps == ps &&
                frame->transaction_id == transaction_id)
                return TRUE;
            mipc_handle_unsolicited (frame);
            mm_mtk_mipc_frame_clear (frame);
        }

        now = g_get_monotonic_time ();
        if (now >= deadline) {
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_TRUNCATED,
                         "Timeout waiting for MIPC message 0x%04x (ps %u, txid %u)",
                         message_id, ps, transaction_id);
            return FALSE;
        }

        remaining = (gint) MIN ((deadline - now) / 1000, (gint64) G_MAXINT);
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll (&pfd, 1, remaining) < 0) {
            if (errno == EINTR)
                continue;
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "poll() on %s failed: %s", MIPC_PORT, g_strerror (errno));
            return FALSE;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "MIPC port %s reported an error", MIPC_PORT);
            return FALSE;
        }
        if (pfd.revents & POLLHUP) {
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "MIPC port %s hung up", MIPC_PORT);
            return FALSE;
        }
        if (!(pfd.revents & POLLIN))
            continue;

        n = read (fd, chunk, sizeof (chunk));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "Couldn't read from %s: %s", MIPC_PORT, g_strerror (errno));
            return FALSE;
        }
        if (n == 0) {
            g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                         "MIPC port %s closed", MIPC_PORT);
            return FALSE;
        }
        g_byte_array_append (buffer, chunk, (guint) n);
    }
}

static gboolean
mipc_exchange (gint             fd,
               GByteArray      *buffer,
               GBytes          *request,
               guint16          message_id,
               guint8           ps,
               guint16          transaction_id,
               guint            timeout_ms,
               MMMtkMipcFrame  *frame,
               GError         **error)
{
    if (!mipc_write_all (fd, request, error))
        return FALSE;
    return mipc_wait_frame (fd, buffer, message_id, ps, transaction_id,
                            timeout_ms, frame, error);
}

/* Opt-in, one-shot queries on the existing connection worker's fd. */
static GBytes *
mipc_snapshot_query (gint          fd,
                     GByteArray   *buffer,
                     guint8        slot,
                     guint16       request_id,
                     guint16       txid,
                     const guint8 *payload,
                     gsize         payload_size)
{
    g_autoptr(GBytes) request = NULL;
    g_autoptr(GError) error = NULL;
    g_autofree gchar *hex = NULL;
    MMMtkMipcFrame    frame = { 0 };
    GBytes          *reply;
    const guint8    *data;
    gsize            size;
    gsize            i;

    request = mm_mtk_mipc_frame_build (request_id, slot, txid, payload, payload_size);
    if (!mipc_exchange (fd, buffer, request, request_id + 1, slot, txid,
                       MIPC_DEACT_TIMEOUT_MS, &frame, &error)) {
        g_debug ("mtk-soc: IMS snapshot req=0x%04x ps=%u failed: %s",
                 request_id, slot, error->message);
        mm_mtk_mipc_frame_clear (&frame);
        return NULL;
    }

    data = g_bytes_get_data (frame.payload, &size);
    /* Both profile catalogs may contain credentials; log only their count prefix. */
    size = MIN (size, (request_id == 0x0107 || request_id == 0x010d) ?
                (gsize) 16 : (gsize) 2048);
    hex = g_malloc (size * 2 + 1);
    for (i = 0; i < size; i++)
        g_snprintf (hex + i * 2, 3, "%02x", data[i]);
    hex[size * 2] = '\0';
    g_debug ("mtk-soc: IMS snapshot cnf=0x%04x ps=%u txid=%u len=%u payload=%s",
             frame.message_id, frame.ps, frame.transaction_id,
             (guint) g_bytes_get_size (frame.payload), hex);
    reply = g_bytes_ref (frame.payload);
    mm_mtk_mipc_frame_clear (&frame);
    return reply;
}

static void
log_apn_profiles (GBytes   *payload,
                  gboolean md_catalog)
{
    /* mipc_md_apn_profile_struct4 from the vendor wire contract (256 bytes). */
    typedef struct {
        guint32 id;
        guint8 plmn[7];
        guint8 active;
        gchar apn[100];
        guint32 apn_index;
        gchar user[64];
        gchar password[64];
        guint32 bearer;
        guint32 apn_type;
        guint8 pdp_type;
        guint8 roaming_type;
        guint8 auth_type;
        guint8 reserved;
    } MdProfileWire;
    /* AP entries use padding instead of active and compression instead of
     * reserved, then append three reserved bytes and enabled. */
    typedef struct {
        MdProfileWire prefix;
        guint8 reserved[3];
        guint8 enabled;
    } ApProfileWire;
    const gsize entry_size = md_catalog ? sizeof (MdProfileWire) : sizeof (ApProfileWire);
    const guint8 *value;
    guint16 length;
    guint8 count;
    guint32 result = G_MAXUINT32;
    guint i;

    G_STATIC_ASSERT (sizeof (MdProfileWire) == 256);
    G_STATIC_ASSERT (sizeof (ApProfileWire) == 260);
    G_STATIC_ASSERT (G_STRUCT_OFFSET (MdProfileWire, user) == 116);
    if (!payload ||
        !mm_mtk_mipc_find_u32_tlv (payload, MM_MTK_MIPC_TLV_RESULT, &result, NULL) ||
        result ||
        !mm_mtk_mipc_find_tlv (payload, 0x0100, &value, &length, NULL) || length != 1)
        return;
    count = value[0];
    if (!count)
        return;
    if (!mm_mtk_mipc_find_tlv (payload, 0x8101, &value, &length, NULL) ||
        length != (gsize) count * entry_size) {
        g_debug ("mtk-soc: %s profile catalog requires another wire layout",
                 md_catalog ? "MD" : "AP");
        return;
    }
    for (i = 0; i < count; i++) {
        MdProfileWire entry;
        g_autofree gchar *name = NULL;
        guint8 state;

        memcpy (&entry, value + i * entry_size, sizeof (entry));
        name = g_strndup (entry.apn, sizeof (entry.apn));
        state = md_catalog ? entry.active :
                value[i * entry_size + G_STRUCT_OFFSET (ApProfileWire, enabled)];
        g_debug ("mtk-soc: %s profile id=%u type=0x%x %s=%u pdp=%u apn=%s",
                 md_catalog ? "MD" : "AP",
                 GUINT32_FROM_LE (entry.id), GUINT32_FROM_LE (entry.apn_type),
                 md_catalog ? "active" : "enabled", state, entry.pdp_type, name);
    }
}

static void
mipc_snapshot_ims (gint        fd,
                   GByteArray *buffer,
                   guint8      slot)
{
    /* IMS_GET_STATE(EVENT=u8 0), and DATA_GET_CALL(ID=u8 cid). */
    const guint8      event[] = { 0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0 };
    const guint8      feature_class[] = { 0x00, 0x01, 0x04, 0x00, 0, 0, 0, 0 };
    const guint8      reg_response[] = { 0x00, 0x01, 0x01, 0x00, 3, 0, 0, 0 };
    guint8            call[] = { 0x01, 0x01, 0x01, 0x00, 0, 0, 0, 0 };
    g_autoptr(GBytes) reply = NULL;
    g_autoptr(GBytes) features = NULL;
    g_autoptr(GBytes) response = NULL;
    g_autoptr(GBytes) config = NULL;
    g_autoptr(GBytes) network_report = NULL;
    g_autoptr(GBytes) ap_profiles = NULL;
    g_autoptr(GBytes) md_profiles = NULL;
    g_autoptr(GBytes) list = NULL;
    g_autoptr(GError) error = NULL;
    guint8            states[MM_MTK_MIPC_CALL_LIST_ENTRIES];
    gsize             n_states = 0;
    guint32           result = G_MAXUINT32;
    guint             i;
    guint             count = 0;

    reply = mipc_snapshot_query (fd, buffer, slot, 0x0a04, 0x60,
                                 event, sizeof (event));
    features = mipc_snapshot_query (fd, buffer, slot, 0x0a02, 0x63,
                                    feature_class, sizeof (feature_class));
    response = mipc_snapshot_query (fd, buffer, slot, 0x0a04, 0x64,
                                    reg_response, sizeof (reg_response));
    config = mipc_snapshot_query (fd, buffer, slot, 0x0213, 0x61, NULL, 0);
    network_report = mipc_snapshot_query (fd, buffer, slot, 0x0a0a, 0x67, NULL, 0);
    ap_profiles = mipc_snapshot_query (fd, buffer, slot, 0x0107, 0x65, NULL, 0);
    md_profiles = mipc_snapshot_query (fd, buffer, slot, 0x010d, 0x66, NULL, 0);
    log_apn_profiles (ap_profiles, FALSE);
    log_apn_profiles (md_profiles, TRUE);
    list = mipc_snapshot_query (fd, buffer, slot, MM_MTK_MIPC_DATA_GET_CALL_LIST_REQ,
                                0x62, NULL, 0);
    if (!list ||
        !mm_mtk_mipc_find_u32_tlv (list, MM_MTK_MIPC_TLV_RESULT, &result, &error) ||
        result ||
        !mm_mtk_mipc_parse_call_list_cnf (list, states, sizeof (states),
                                          &n_states, &error))
        return;

    for (i = 0; i < n_states && count < 8; i++) {
        g_autoptr(GBytes) info = NULL;

        if (!states[i])
            continue;
        call[4] = (guint8) i;
        info = mipc_snapshot_query (fd, buffer, slot, 0x0205,
                                    (guint16) (0x70 + count), call, sizeof (call));
        count++;
    }
}

/*****************************************************************************/
/* Connect                                                                    */

typedef struct {
    MMBroadbandModem *modem;
    gchar            *apn;
    gchar            *user;
    gchar            *password;
    guint8            slots[MIPC_MAX_SLOT_ATTEMPTS];
    guint             n_slots;
} MtkSocConnectContext;

typedef struct {
    gint                fd;
    guint8              slot;
    MMMtkMipcDataActCnf cnf;
    GByteArray         *pending;
} MtkSocConnectResult;

/* A data call left up by a previous session makes the D2 layer refuse a new
 * DATA_ACT with D2CPM_IN_USE (0x001416D7). Ask the modem which cids are still
 * active and deactivate them, so the following DATA_ACT attempt can succeed.
 * Device-measured contract (run18): the request needs ps = slot (ps = 0xff is
 * refused with result 21); the CNF's 0x0100 byte array is indexed by the call
 * id itself (an accepted DATA_ACT whose CNF ID is 1 shows entry[1]; index 0 is
 * unused), and DEACT uses that same id. Returns FALSE only on a transport or
 * parse error; *n_cleared counts the cids that were actually deactivated. */
static gboolean
mipc_clear_active_calls (gpointer     source_object,
                         gint         fd,
                         GByteArray  *buffer,
                         guint8       slot,
                         guint       *n_cleared,
                         GError     **error)
{
    g_autoptr(GBytes) request = NULL;
    MMMtkMipcFrame    frame = { 0 };
    guint8            states[MM_MTK_MIPC_CALL_LIST_ENTRIES];
    gsize             n_states = 0;
    guint             i;

    *n_cleared = 0;

    request = mm_mtk_mipc_data_get_call_list_request (slot, MIPC_TXID_CALL_LIST);
    if (!mipc_exchange (fd, buffer, request, MM_MTK_MIPC_DATA_GET_CALL_LIST_CNF, slot,
                        MIPC_TXID_CALL_LIST, MIPC_DEACT_TIMEOUT_MS, &frame, error))
        return FALSE;

    if (!mm_mtk_mipc_parse_call_list_cnf (frame.payload, states, sizeof (states),
                                          &n_states, error)) {
        mm_mtk_mipc_frame_clear (&frame);
        return FALSE;
    }
    mm_mtk_mipc_frame_clear (&frame);

    for (i = 0; i < n_states; i++) {
        g_autoptr(GBytes) deact = NULL;
        guint32           result = 0;

        if (!states[i])
            continue;

        deact = mm_mtk_mipc_data_deact_request (slot, MIPC_TXID_DATA_DEACT, (guint8) i,
                                                MM_MTK_MIPC_DEACT_REASON_FORCE_TO_LOCAL_RELEASE,
                                                error);
        if (!deact)
            return FALSE;

        if (!mipc_exchange (fd, buffer, deact, MM_MTK_MIPC_DATA_DEACT_CNF, slot,
                            MIPC_TXID_DATA_DEACT, MIPC_DEACT_TIMEOUT_MS, &frame, error))
            return FALSE;

        if (!mm_mtk_mipc_find_u32_tlv (frame.payload, MM_MTK_MIPC_TLV_RESULT,
                                       &result, error)) {
            mm_mtk_mipc_frame_clear (&frame);
            return FALSE;
        }
        mm_mtk_mipc_frame_clear (&frame);

        if (result == 0) {
            (*n_cleared)++;
            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                        "deactivated stale data call cid %u on SIM slot %u", i, slot);
        } else {
            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                        "DATA_DEACT for cid %u on SIM slot %u returned result %u",
                        i, slot, result);
        }
    }

    return TRUE;
}

static void
connect_context_free (MtkSocConnectContext *ctx)
{
    g_free (ctx->apn);
    g_free (ctx->user);
    g_free (ctx->password);
    g_clear_object (&ctx->modem);
    g_free (ctx);
}

static void
connect_result_free (MtkSocConnectResult *result)
{
    if (result->fd >= 0)
        close (result->fd);
    g_clear_pointer (&result->pending, g_byte_array_unref);
    g_free (result);
}

static gboolean
mipc_handshake (gint            fd,
                GByteArray     *buffer,
                MMMtkMipcFrame *frame,
                GError        **error)
{
    g_autoptr(GBytes) request = NULL;
    guint32 result = 0;

    /* TEST_REQ / TEST_CNF: liveness only, the result code is informational. */
    request = mm_mtk_mipc_test_request (0xff, MIPC_TXID_TEST);
    if (!mipc_exchange (fd, buffer, request, MM_MTK_MIPC_TEST_CNF, 0xff,
                        MIPC_TXID_TEST, MIPC_TEST_TIMEOUT_MS, frame, error))
        return FALSE;
    mm_mtk_mipc_frame_clear (frame);

    /* OPEN_REQ / OPEN_CNF: result 0x0000 must be 0. */
    g_clear_pointer (&request, g_bytes_unref);
    request = mm_mtk_mipc_open_request (0xff, MIPC_TXID_OPEN, MIPC_CLIENT_NAME, error);
    if (!request)
        return FALSE;
    if (!mipc_exchange (fd, buffer, request, MM_MTK_MIPC_OPEN_CNF, 0xff,
                        MIPC_TXID_OPEN, MIPC_OPEN_TIMEOUT_MS, frame, error))
        return FALSE;
    if (!mm_mtk_mipc_find_u32_tlv (frame->payload, MM_MTK_MIPC_TLV_RESULT,
                                   &result, error)) {
        mm_mtk_mipc_frame_clear (frame);
        return FALSE;
    }
    mm_mtk_mipc_frame_clear (frame);
    if (result != 0) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "MIPC OPEN refused with result %u", result);
        return FALSE;
    }

    /* qqcandy: subscribe to the unsolicited messages we care about.  Best
     * effort -- the modem answers result=21 (not supported) for ids it does not
     * implement, which is not an error for us. */
    {
        static const guint16 inds[] = {
            0x4a00, /* IMS_CONFIG_IND           */
            0x4a01, /* IMS_STATE_IND            */
            0x4a02, /* IMS_SUPPORT_ECC_IND      */
            0x4a03, /* IMS_PDN_IND              */
            0x4a04, /* IMS_NAPTR_IND            */
            0x4a05, /* IMS_REG_IND              */
            0x4a06, /* IMS_SIP_REG_INFO_IND     */
            0x4a07, /* IMS_VOPS_IND             */
            0x4a08, /* IMS_REG_REMAIN_TIME_IND  */
            0x4a09, /* IMS_UI_IND               */
            0x4401, /* NW_REGISTER_IND          */
            0x4302, /* INTERNAL_EIF_IND         */
            0x4008, /* SYS_EL2_IP_DL_IND         */
            0x4201, /* DATA_ACT_CALL_IND        */
            0x4202, /* DATA_DEACT_CALL_IND      */
            0x420a, /* DATA_MD_ACT_CALL_IND     */
            0x420b, /* DATA_MD_DEACT_CALL_IND   */
            0x420f, /* DATA_TIMER_IND           */
            0x4212, /* DATA_NETWORK_REJECT_CAUSE_IND */
            0x4218  /* DATA_PDN_NW_CAUSE_IND    */
        };
        guint i;
        guint subscribed = 0;
        guint requested = 0;

        for (i = 0; i < G_N_ELEMENTS (inds); i++) {
            g_autoptr(GBytes) sub = NULL;
            g_autoptr(GError)  sub_error = NULL;
            guint32           sub_result = G_MAXUINT32;

            if (inds[i] >= 0x4200 && inds[i] < 0x4300 &&
                g_strcmp0 (g_getenv ("QQC_MIPC_IMS_DIAGNOSTICS"), "1") != 0)
                continue;
            requested++;
            sub = mm_mtk_mipc_register_ind_request (0xff,
                                                    (guint16) (MIPC_TXID_REGIND + i),
                                                    inds[i], &sub_error);
            if (!sub) {
                g_debug ("mtk-soc: cannot build IND subscribe for 0x%04x: %s",
                         inds[i], sub_error ? sub_error->message : "?");
                continue;
            }
            if (!mipc_exchange (fd, buffer, sub, MM_MTK_MIPC_REGISTER_IND_CNF, 0xff,
                                (guint16) (MIPC_TXID_REGIND + i),
                                MIPC_TEST_TIMEOUT_MS, frame, &sub_error)) {
                g_debug ("mtk-soc: IND subscribe 0x%04x got no CNF: %s", inds[i],
                         sub_error ? sub_error->message : "?");
                continue;
            }
            if (!mm_mtk_mipc_find_u32_tlv (frame->payload, MM_MTK_MIPC_TLV_RESULT,
                                          &sub_result, &sub_error)) {
                g_debug ("mtk-soc: IND subscribe 0x%04x invalid CNF: %s",
                         inds[i], sub_error ? sub_error->message : "?");
            } else if (sub_result != 0) {
                g_debug ("mtk-soc: IND subscribe 0x%04x refused with result %u",
                         inds[i], sub_result);
            } else {
                subscribed++;
                g_debug ("mtk-soc: IND subscribe 0x%04x accepted", inds[i]);
            }
            mm_mtk_mipc_frame_clear (frame);
        }
        g_debug ("mtk-soc: subscribed to %u/%u modem IND message ids",
                 subscribed, requested);
    }
    return TRUE;
}

static void
connect_thread (GTask        *task,
                gpointer      source_object,
                gpointer      task_data,
                GCancellable *cancellable)
{
    MtkSocConnectContext *ctx = task_data;
    g_autoptr(GByteArray) buffer = NULL;
    g_autoptr(GError)     error = NULL;
    MMMtkMipcFrame        frame = { 0 };
    MtkSocConnectResult  *result = NULL;
    gint                  fd = -1;
    guint                 i;

    if (g_cancellable_set_error_if_cancelled (cancellable, &error))
        goto out;

    fd = open (MIPC_PORT, O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        g_set_error (&error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "Couldn't open %s: %s", MIPC_PORT, g_strerror (errno));
        goto out;
    }

    buffer = g_byte_array_new ();
    if (!mipc_handshake (fd, buffer, &frame, &error))
        goto out;

    for (i = 0; i < ctx->n_slots && !result; i++) {
        guint attempt;

        /* Two attempts per slot: the second one only after clearing a data
         * call left up by a previous session (D2CPM_IN_USE). */
        for (attempt = 0; attempt < 2 && !result; attempt++) {
            g_autoptr(GBytes)   request = NULL;
            MMMtkMipcDataActCnf cnf;
            guint16             txid = (attempt == 0) ? MIPC_TXID_DATA_ACT
                                                      : MIPC_TXID_DATA_ACT_RETRY;

            if (g_cancellable_set_error_if_cancelled (cancellable, &error))
                goto out;

            request = mm_mtk_mipc_data_act_request (ctx->slots[i], txid,
                                                    ctx->apn, ctx->user, ctx->password,
                                                    &error);
            if (!request)
                goto out;

            /* A transport error (timeout, EOF) leaves the channel ambiguous, so
             * it is fatal; only a well-formed refusal allows the next attempt
             * or the second slot. */
            if (!mipc_exchange (fd, buffer, request, MM_MTK_MIPC_DATA_ACT_CNF,
                                ctx->slots[i], txid,
                                MIPC_DATA_TIMEOUT_MS, &frame, &error))
                goto out;

            if (!mm_mtk_mipc_parse_data_act_cnf (frame.payload, &cnf, &error))
                goto out;
            mm_mtk_mipc_frame_clear (&frame);

            if (cnf.result == 0) {
                /* Bring the IMS bearer up on the same MIPC connection.  On an
                 * LTE/NR-only network there is no CS domain, so both VoLTE and
                 * MO SMS depend on IMS being registered; without the dedicated
                 * IMS PDN the modem never starts SIP registration at all.
                 * Measured 2026-10-07: a full DATA_ACT frame with APN "ims" and
                 * ps = slot is accepted (CNF result 0) and the modem then emits
                 * +EIF: <id>, ifup, ... for the new interface.  The REUSE_ONLY
                 * variant is refused (0x150102) because there is nothing to
                 * reuse yet.  Best effort: a refusal must not fail the data
                 * call. */
                {
                    g_autoptr(GBytes)   ims_request = NULL;
                    g_autoptr(GError)   ims_error = NULL;
                    MMMtkMipcDataActCnf ims_cnf;

                    /*
                     * Stock order: DATA_RETRY_TIMER_REQ (0x021b) first, then the
                     * DATA_ACT.  The modem refuses the activation otherwise.
                     * Best effort -- a missing CNF must not fail the data call.
                     */
                    {
                        g_autoptr(GBytes) timer_request = NULL;
                        gsize             timer_len = 0;
                        const guint8     *timer_data = NULL;

                        /*
                         * Fire and forget, exactly like the stock stack: it sends
                         * 0x021b and the DATA_ACT back to back (txid 0x0466 then
                         * 0x0467).  The modem answers this one on the indication
                         * channel -- observed "modem IND 0x021c ... len=8
                         * 0000040002000000" -- so waiting for a CNF here only
                         * stalls the activation for the entire timeout.
                         */
                        timer_request = mm_mtk_mipc_ims_retry_timer_request (ctx->slots[i],
                                                                            MIPC_TXID_IMS_RETRY_TIMER);
                        if (timer_request)
                            timer_data = g_bytes_get_data (timer_request, &timer_len);
                        if (timer_data && timer_len > 0 &&
                            write (fd, timer_data, timer_len) != (ssize_t) timer_len)
                            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                        "IMS DATA_RETRY_TIMER write failed: %s",
                                        g_strerror (errno));
                    }

                    /*
                     * Use the FULL frame here, not the minimal four-TLV one.
                     * Measured on this modem: the minimal frame is answered with
                     * 0x150102 (the "nothing to reuse" refusal, same code the
                     * REUSE_ONLY variant gets) and a 312-byte CNF carrying no IP
                     * parameters at all, while the full frame returns a CNF with
                     * the interface and the modem emits "+EIF: <id>, ifup, ...".
                     * Now that 0x021b goes out first, this is the combination
                     * that has not been tried yet.
                     */
                    ims_request = mm_mtk_mipc_data_act_request_typed (ctx->slots[i],
                                                                     MIPC_TXID_IMS_ACT,
                                                                     "ims", NULL, NULL,
                                                                     2 /* APN_TYPE_IMS */,
                                                                     0, &ims_error);
                    if (!ims_request) {
                        mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                    "cannot build IMS DATA_ACT: %s",
                                    ims_error ? ims_error->message : "?");
                    } else if (!mipc_exchange (fd, buffer, ims_request,
                                               MM_MTK_MIPC_DATA_ACT_CNF,
                                               ctx->slots[i], MIPC_TXID_IMS_ACT,
                                               MIPC_DATA_TIMEOUT_MS, &frame, &ims_error)) {
                        mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                    "IMS DATA_ACT got no CNF: %s",
                                    ims_error ? ims_error->message : "?");
                    } else if (!mm_mtk_mipc_parse_data_act_cnf (frame.payload, &ims_cnf,
                                                                &ims_error)) {
                        /* The accepted IMS DATA_ACT answers with a much larger
                         * frame than the refusal path, and the generic parser
                         * does not understand it.  Dump enough of it (plus any
                         * result TLV we can find) to see what the modem said. */
                        const guint8 *raw = NULL;
                        gsize         raw_len = 0;
                        guint32       raw_result = G_MAXUINT32;
                        g_autofree gchar *hex = NULL;
                        gsize         n;
                        gsize         k;

                        if (frame.payload)
                            raw = g_bytes_get_data (frame.payload, &raw_len);
                        n = MIN (raw_len, (gsize) 96);
                        hex = g_malloc0 (n * 2 + 1);
                        for (k = 0; k < n; k++)
                            g_snprintf (hex + k * 2, 3, "%02x", raw[k]);
                        if (mm_mtk_mipc_find_u32_tlv (frame.payload,
                                                      MM_MTK_MIPC_TLV_RESULT,
                                                      &raw_result, NULL))
                            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                        "IMS DATA_ACT CNF len=%u result=%u hex=%s",
                                        (guint) raw_len, raw_result, hex);
                        else
                            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                        "IMS DATA_ACT CNF len=%u (no result TLV) hex=%s",
                                        (guint) raw_len, hex);
                    } else if (ims_cnf.result != 0) {
                        mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                    "IMS DATA_ACT on SIM slot %u refused with result %u",
                                    ctx->slots[i], ims_cnf.result);
                    } else {
                        mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                                    "IMS bearer up on SIM slot %u (call id %u, iface %u)",
                                    ctx->slots[i], ims_cnf.call_id, ims_cnf.interface_id);
                    }
                    mm_mtk_mipc_frame_clear (&frame);
                }

                if (g_strcmp0 (g_getenv ("QQC_MIPC_IMS_SNAPSHOT"), "1") == 0)
                    mipc_snapshot_ims (fd, buffer, ctx->slots[i]);
                result = g_new0 (MtkSocConnectResult, 1);
                result->fd = fd;
                result->slot = ctx->slots[i];
                result->cnf = cnf;
                result->pending = g_steal_pointer (&buffer);
                fd = -1; /* ownership moved to the result */
                break;
            }

            if (cnf.result == MM_MTK_MIPC_RESULT_D2CPM_IN_USE && attempt == 0) {
                guint n_cleared = 0;

                if (!mipc_clear_active_calls (source_object, fd, buffer, ctx->slots[i],
                                              &n_cleared, &error))
                    goto out;

                mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                            "DATA_ACT on SIM slot %u refused with D2CPM_IN_USE; "
                            "cleared %u stale data call(s), retrying",
                            ctx->slots[i], n_cleared);
                if (n_cleared > 0)
                    continue;   /* -> retry attempt for the same slot */
            }

            mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                        "DATA_ACT on SIM slot %u refused with result %u",
                        ctx->slots[i], cnf.result);
            break;
        }
    }

    if (!result)
        g_set_error (&error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "No MIPC DATA_ACT succeeded on SIM slot(s) 1..2");

out:
    mm_mtk_mipc_frame_clear (&frame);
    if (result) {
        g_task_return_pointer (task, result, (GDestroyNotify) connect_result_free);
        return;
    }
    if (fd >= 0)
        close (fd);
    if (!error)
        g_set_error_literal (&error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC connect failed");
    g_task_return_error (task, g_steal_pointer (&error));
}

static void
connect_3gpp (MMBroadbandBearer   *self,
              MMBroadbandModem    *modem,
              MMPortSerialAt      *primary,
              MMPortSerialAt      *secondary,
              GCancellable        *cancellable,
              GAsyncReadyCallback  callback,
              gpointer             user_data)
{
    MtkSocConnectContext *ctx;
    MMBearerProperties   *properties;
    GTask                *task;
    guint                 primary_slot;
    guint                 i;
    guint                 n = 0;

    properties = mm_base_bearer_peek_config (MM_BASE_BEARER (self));

    ctx = g_new0 (MtkSocConnectContext, 1);
    ctx->modem = g_object_ref (modem);
    ctx->apn = g_strdup (mm_bearer_properties_get_apn (properties));
    ctx->user = g_strdup (mm_bearer_properties_get_user (properties));
    ctx->password = g_strdup (mm_bearer_properties_get_password (properties));

    /* Try the slot chosen during modem initialization first, then 1 and 2,
     * bounded to MIPC_MAX_SLOT_ATTEMPTS. */
    primary_slot = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (modem),
                                                        MM_MTK_SOC_PRIMARY_SLOT_DATA));
    if (primary_slot >= 1 && primary_slot <= 2)
        ctx->slots[n++] = (guint8) primary_slot;
    for (i = 1; i <= 2 && n < MIPC_MAX_SLOT_ATTEMPTS; i++) {
        guint j;
        gboolean duplicate = FALSE;

        for (j = 0; j < n; j++) {
            if (ctx->slots[j] == i) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate)
            ctx->slots[n++] = (guint8) i;
    }
    ctx->n_slots = n;

    mm_obj_dbg (self, "launching MIPC direct-IP connection (slots %u,%u)",
                ctx->slots[0], ctx->slots[1]);

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify) connect_context_free);
    g_task_run_in_thread (task, connect_thread);
    g_object_unref (task);
}

static MMBearerConnectResult *
connect_3gpp_finish (MMBroadbandBearer *self,
                     GAsyncResult      *res,
                     GError           **error)
{
    MMBroadbandBearerMtkSoc        *bearer = MM_BROADBAND_BEARER_MTK_SOC (self);
    MMBroadbandBearerMtkSocPrivate *priv;
    MtkSocConnectResult            *mtk;
    MMBearerIpConfig               *ipv4 = NULL;
    MMBearerConnectResult          *result = NULL;
    g_autoptr(MMBaseModem)          modem = NULL;
    g_autoptr(MMPort)               port = NULL;
    g_autofree gchar               *address = NULL;
    g_autofree gchar               *gateway = NULL;
    g_autofree gchar               *dns1 = NULL;
    g_autofree gchar               *dns2 = NULL;
    const gchar                    *dns[3] = { NULL, NULL, NULL };
    guint                           mtu;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (bearer);

    mtk = g_task_propagate_pointer (G_TASK (res), error);
    if (!mtk)
        return NULL;

    /* The ccmni index is derived from the interface id; a transIntfId that
     * disagrees means the confirmation was misread. */
    if (mtk->cnf.trans_intf_id != 0 &&
        mtk->cnf.interface_id != (mtk->cnf.trans_intf_id % 100)) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "MIPC interface id %u does not match transIntfId %u",
                     mtk->cnf.interface_id, mtk->cnf.trans_intf_id);
        goto out;
    }

    address = ipv4_to_string (mtk->cnf.ipv4);
    if (g_str_equal (address, "0.0.0.0")) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC DATA_ACT returned no IPv4 address");
        goto out;
    }

    /* The modem property is a plain (non-construct) property, so it is not set
     * yet when constructed() runs; fetch it at use time like the stock bearers. */
    g_object_get (self, MM_BASE_BEARER_MODEM, &modem, NULL);
    if (!modem) {
        g_set_error_literal (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                             "MIPC bearer has no modem attached");
        goto out;
    }

    port = mtk_soc_net_port (MM_BROADBAND_MODEM (modem), mtk->cnf.interface_id);
    if (!port) {
        g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                     "Couldn't find the ccmni%u data port", mtk->cnf.interface_id);
        goto out;
    }

    mtu = mtk->cnf.mtu ? mtk->cnf.mtu : MIPC_DEFAULT_MTU;

    ipv4 = mm_bearer_ip_config_new ();
    mm_bearer_ip_config_set_method (ipv4, MM_BEARER_IP_METHOD_STATIC);
    mm_bearer_ip_config_set_address (ipv4, address);
    mm_bearer_ip_config_set_prefix (ipv4, mtk->cnf.ipv4_prefix);
    gateway = ipv4_to_string (mtk->cnf.gateway);
    if (!g_str_equal (gateway, "0.0.0.0"))
        mm_bearer_ip_config_set_gateway (ipv4, gateway);
    dns1 = ipv4_to_string (mtk->cnf.dns[0]);
    dns2 = ipv4_to_string (mtk->cnf.dns[1]);
    if (!g_str_equal (dns1, "0.0.0.0"))
        dns[0] = dns1;
    if (!g_str_equal (dns2, "0.0.0.0"))
        dns[1] = dns2;
    mm_bearer_ip_config_set_dns (ipv4, dns);
    mm_bearer_ip_config_set_mtu (ipv4, mtu);

    result = mm_bearer_connect_result_new (port, ipv4, NULL);
    /* Remember the MIPC call id so disconnect can deactivate it. */
    mm_bearer_connect_result_set_profile_id (result, (gint) mtk->cnf.call_id);

    g_mutex_lock (&priv->mutex);
    priv->fd = mtk->fd;
    priv->slot = mtk->slot;
    g_clear_pointer (&priv->ind_buffer, g_byte_array_unref);
    priv->ind_buffer = g_steal_pointer (&mtk->pending);
    g_mutex_unlock (&priv->mutex);
    mtk->fd = -1; /* ownership moved to the private data */
    mipc_spi_start (MM_BROADBAND_BEARER_MTK_SOC (self));

    mm_obj_dbg (self, "connected %s (call id %u, prefix %u, mtu %u)",
                mm_port_get_device (port), mtk->cnf.call_id,
                mtk->cnf.ipv4_prefix, mtu);

out:
    if (mtk)
        connect_result_free (mtk);
    g_clear_object (&ipv4);
    return result;
}

/*****************************************************************************/
/* Disconnect                                                                 */

typedef struct {
    gint   fd;
    guint8 slot;
    guint8 call_id;
    MMMtkIpsec *ipsec;
} MtkSocDisconnectContext;

static void
disconnect_context_free (MtkSocDisconnectContext *ctx)
{
    if (ctx->ipsec) {
        if (ctx->fd >= 0)
            mipc_spi_close_client (ctx->fd);
        mm_mtk_ipsec_free (ctx->ipsec);
    }
    if (ctx->fd >= 0)
        close (ctx->fd);
    g_free (ctx);
}

static void
disconnect_thread (GTask        *task,
                   gpointer      source_object,
                   gpointer      task_data,
                   GCancellable *cancellable)
{
    MtkSocDisconnectContext *ctx = task_data;
    g_autoptr(GByteArray)    buffer = NULL;
    g_autoptr(GError)        error = NULL;
    g_autoptr(GBytes)        request = NULL;
    MMMtkMipcFrame           frame = { 0 };

    buffer = g_byte_array_new ();
    request = mm_mtk_mipc_data_deact_request (ctx->slot, MIPC_TXID_DATA_DEACT,
                                              ctx->call_id,
                                              MM_MTK_MIPC_DEACT_REASON_NORMAL, &error);
    if (request &&
        !mipc_exchange (ctx->fd, buffer, request, MM_MTK_MIPC_DATA_DEACT_CNF,
                        ctx->slot, MIPC_TXID_DATA_DEACT,
                        MIPC_DEACT_TIMEOUT_MS, &frame, &error)) {
        /* Best effort: the port is closed anyway below. */
    }

    mm_mtk_mipc_frame_clear (&frame);
    if (error)
        mm_obj_dbg (MM_BROADBAND_BEARER_MTK_SOC (source_object),
                    "best-effort MIPC DATA_DEACT failed: %s", error->message);

    /* The context still owns the fd; disconnect_context_free() closes it. */
    g_task_return_boolean (task, TRUE);
}

static void
disconnect_3gpp (MMBroadbandBearer   *self,
                 MMBroadbandModem    *modem,
                 MMPortSerialAt      *primary,
                 MMPortSerialAt      *secondary,
                 MMPort              *data,
                 guint                cid,
                 GAsyncReadyCallback  callback,
                 gpointer             user_data)
{
    MMBroadbandBearerMtkSoc        *bearer = MM_BROADBAND_BEARER_MTK_SOC (self);
    MMBroadbandBearerMtkSocPrivate *priv;
    MtkSocDisconnectContext        *ctx;
    GTask                          *task;
    gint                            fd;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (bearer);

    g_mutex_lock (&priv->mutex);
    mipc_spi_stop_sources (priv);
    fd = priv->fd;
    priv->fd = -1;
    ctx = g_new0 (MtkSocDisconnectContext, 1);
    ctx->fd = fd;
    ctx->slot = priv->slot;
    ctx->call_id = (guint8) cid;
    ctx->ipsec = priv->ipsec;
    priv->ipsec = NULL;
    g_mutex_unlock (&priv->mutex);

    task = g_task_new (self, NULL, callback, user_data);

    if (ctx->fd < 0) {
        /* Nothing was left open (connect failed); nothing to deactivate. */
        disconnect_context_free (ctx);
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    g_task_set_task_data (task, ctx, (GDestroyNotify) disconnect_context_free);
    g_task_run_in_thread (task, disconnect_thread);
    g_object_unref (task);
}

static gboolean
disconnect_3gpp_finish (MMBroadbandBearer *self,
                        GAsyncResult      *res,
                        GError           **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

/*****************************************************************************/

static MMPort *
mtk_soc_net_port (MMBroadbandModem *modem,
                  guint32           interface_id)
{
    g_autofree gchar *name = NULL;
    g_autofree gchar *alt = NULL;
    MMPort           *port;

    if (!modem)
        return NULL;

    /* mm_base_modem_get_port() already returns a new reference. */
    name = g_strdup_printf ("ccmni%u", interface_id);
    port = mm_base_modem_get_port (MM_BASE_MODEM (modem), name);
    if (!port) {
        /* Tolerate a subsystem-prefixed device name. */
        alt = g_strdup_printf ("net/ccmni%u", interface_id);
        port = mm_base_modem_get_port (MM_BASE_MODEM (modem), alt);
    }

    return port;
}

static void
constructed (GObject *object)
{
    /* MM_BASE_BEARER_MODEM is a plain (non-construct) property, so it is not
     * set yet here; connect_3gpp_finish() fetches it on demand instead. */
    G_OBJECT_CLASS (mm_broadband_bearer_mtk_soc_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
    MMBroadbandBearerMtkSoc        *self = MM_BROADBAND_BEARER_MTK_SOC (object);
    MMBroadbandBearerMtkSocPrivate *priv;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (self);

    g_mutex_lock (&priv->mutex);
    mipc_spi_stop_sources (priv);
    if (priv->ipsec) {
        if (priv->fd >= 0)
            mipc_spi_close_client (priv->fd);
        mm_mtk_ipsec_free (priv->ipsec);
        priv->ipsec = NULL;
    }
    if (priv->fd >= 0) {
        close (priv->fd);
        priv->fd = -1;
    }
    g_mutex_unlock (&priv->mutex);

    G_OBJECT_CLASS (mm_broadband_bearer_mtk_soc_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
    MMBroadbandBearerMtkSoc        *self = MM_BROADBAND_BEARER_MTK_SOC (object);
    MMBroadbandBearerMtkSocPrivate *priv;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (self);
    g_clear_pointer (&priv->ind_buffer, g_byte_array_unref);
    g_mutex_clear (&priv->mutex);

    G_OBJECT_CLASS (mm_broadband_bearer_mtk_soc_parent_class)->finalize (object);
}

static void
mm_broadband_bearer_mtk_soc_init (MMBroadbandBearerMtkSoc *self)
{
    MMBroadbandBearerMtkSocPrivate *priv;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (self);
    priv->fd = -1;
    priv->slot = 1;
    g_mutex_init (&priv->mutex);
    priv->ind_buffer = g_byte_array_new ();
}

/* Connection status.
 *
 * The generic MMBroadbandBearer implementation asks the modem with AT+CGACT? and
 * requires a context whose cid matches the bearer's profile id.  This MD answers
 * AT+CGACT? with a bare OK (the data call is up on ccmni0/ccmni1 regardless), so
 * ModemManager logged, every few seconds:
 *
 *   <wrn> [modem0/bearer0] checking if connected failed:
 *         PDP context not found in the known contexts list
 *
 * Our bearer knows the truth directly: priv->fd is the MIPC data-call socket and
 * it stays open exactly while the call is up (disconnect and dispose close it and
 * set it to -1).  Answer from that instead of from an AT command this firmware
 * does not implement. */
static void
load_connection_status (MMBaseBearer        *self,
                        GAsyncReadyCallback  callback,
                        gpointer             user_data)
{
    MMBroadbandBearerMtkSoc        *bearer = MM_BROADBAND_BEARER_MTK_SOC (self);
    MMBroadbandBearerMtkSocPrivate *priv;
    MMBearerConnectionStatus        status;
    GTask                          *task;

    priv = mm_broadband_bearer_mtk_soc_get_instance_private (bearer);

    mm_obj_dbg (self, "connection status poll tick (mipc fd=%d)", priv->fd);

    g_mutex_lock (&priv->mutex);
    if (priv->fd >= 0 && priv->ind_buffer)
        mipc_drain_unsolicited (priv);
    status = (priv->fd >= 0) ? MM_BEARER_CONNECTION_STATUS_CONNECTED
                             : MM_BEARER_CONNECTION_STATUS_DISCONNECTED;
    g_mutex_unlock (&priv->mutex);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_int (task, (gssize) status);
    g_object_unref (task);
}

static MMBearerConnectionStatus
load_connection_status_finish (MMBaseBearer  *self,
                               GAsyncResult  *res,
                               GError       **error)
{
    return (MMBearerConnectionStatus) g_task_propagate_int (G_TASK (res), error);
}

static void
mm_broadband_bearer_mtk_soc_class_init (MMBroadbandBearerMtkSocClass *klass)
{
    GObjectClass           *object_class = G_OBJECT_CLASS (klass);
    MMBroadbandBearerClass *broadband_bearer_class = MM_BROADBAND_BEARER_CLASS (klass);

    object_class->constructed = constructed;
    object_class->dispose     = dispose;
    object_class->finalize    = finalize;

    broadband_bearer_class->connect_3gpp        = connect_3gpp;
    broadband_bearer_class->connect_3gpp_finish = connect_3gpp_finish;
    broadband_bearer_class->disconnect_3gpp     = disconnect_3gpp;
    broadband_bearer_class->disconnect_3gpp_finish = disconnect_3gpp_finish;

    /* Answer the periodic "is it still connected?" check from the MIPC
     * socket instead of the unimplemented AT+CGACT? (see above). */
    MM_BASE_BEARER_CLASS (klass)->load_connection_status = load_connection_status;
    MM_BASE_BEARER_CLASS (klass)->load_connection_status_finish = load_connection_status_finish;

    /* qqcandy: mm-base-bearer.c only polls the bearer when the class provides
     * reload_connection_status; without it there is no periodic call at all, so
     * the socket drain in load_connection_status() would never run and the
     * modem's unsolicited messages would stay unread.  The header explicitly
     * allows sharing the same implementation with load_connection_status(). */
#if defined WITH_SUSPEND_RESUME
    MM_BASE_BEARER_CLASS (klass)->reload_connection_status = load_connection_status;
    MM_BASE_BEARER_CLASS (klass)->reload_connection_status_finish = load_connection_status_finish;
#endif
}
