/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "mm-mtk-ipsec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define XFRM_REPLY_TIMEOUT_MS 500
#define SPI_RESERVATION_LIMIT 128

typedef struct {
    MMMtkMipcSpiRequest request;
    guint32 reqid;
    guint32 spi;
    gboolean expired;
} SpiReservation;

struct _MMMtkIpsec {
    gint fd;
    guint32 sequence;
    GArray *reservations;
};

static gboolean
ipsec_error (GError **error, const gchar *operation, gint code)
{
    g_set_error (error, MM_MTK_MIPC_ERROR, MM_MTK_MIPC_ERROR_INVALID,
                 "XFRM %s: %s", operation, g_strerror (code));
    return FALSE;
}

static gint
reply_error (GError **error, const gchar *operation, gint code)
{
    ipsec_error (error, operation, code);
    return -code;
}

static void
note_expiry (MMMtkIpsec *self, const struct xfrm_user_expire *event)
{
    guint i;

    if (!event->hard)
        return;
    for (i = 0; i < self->reservations->len; i++) {
        SpiReservation *owned = &g_array_index (self->reservations, SpiReservation, i);

        if (owned->reqid == event->state.reqid &&
            owned->spi == ntohl (event->state.id.spi) &&
            event->state.id.proto == owned->request.protocol &&
            event->state.family == (owned->request.address_len == 4 ? AF_INET : AF_INET6) &&
            memcmp (&event->state.id.daddr, owned->request.destination,
                    owned->request.address_len) == 0)
            owned->expired = TRUE;
    }
}

/* One socket serializes unicast replies and the EXPIRE multicast. Expiry events
 * are queued in the reservation table, never answered recursively mid-request. */
static gint
receive_reply (MMMtkIpsec *self, guint32 sequence, guint16 expected,
               struct xfrm_usersa_info *state, gboolean wait, GError **error)
{
    gint64 deadline = g_get_monotonic_time () + XFRM_REPLY_TIMEOUT_MS * 1000;

    for (;;) {
        union { struct nlmsghdr alignment; guint8 bytes[8192]; } buffer;
        struct sockaddr_nl peer = { 0 };
        struct iovec iov = { buffer.bytes, sizeof (buffer.bytes) };
        struct msghdr msg = { 0 };
        struct nlmsghdr *header;
        ssize_t n;
        gint length;

        if (wait) {
            struct pollfd pfd = { self->fd, POLLIN, 0 };
            gint64 remaining = deadline - g_get_monotonic_time ();
            gint ready;

            if (remaining <= 0)
                return reply_error (error, "reply timeout", ETIMEDOUT);
            ready = poll (&pfd, 1, (gint) MAX (1, remaining / 1000));
            if (ready < 0 && errno == EINTR)
                continue;
            if (ready < 0)
                return reply_error (error, "poll", errno);
            if (!ready)
                continue;
        }
        msg.msg_name = &peer;
        msg.msg_namelen = sizeof (peer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        n = recvmsg (self->fd, &msg, MSG_DONTWAIT);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && errno == EAGAIN) {
            if (wait)
                continue;
            return 0;
        }
        if (n < 0)
            return reply_error (error, "recvmsg", errno);
        if (!n || (msg.msg_flags & MSG_TRUNC) ||
            msg.msg_namelen != sizeof (peer) || peer.nl_pid != 0)
            return reply_error (error, "invalid datagram", EPROTO);
        length = (gint) n;
        for (header = (struct nlmsghdr *) buffer.bytes; NLMSG_OK (header, length);
             header = NLMSG_NEXT (header, length)) {
            if (header->nlmsg_type == XFRM_MSG_EXPIRE &&
                header->nlmsg_len >= NLMSG_LENGTH (sizeof (struct xfrm_user_expire))) {
                note_expiry (self, NLMSG_DATA (header));
                continue;
            }
            if (!wait || header->nlmsg_seq != sequence)
                continue;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *reply;

                if (header->nlmsg_len < NLMSG_LENGTH (sizeof (*reply)))
                    return reply_error (error, "short error", EPROTO);
                reply = NLMSG_DATA (header);
                if (reply->error) {
                    ipsec_error (error, "request", -reply->error);
                    return reply->error;
                }
                if (expected == NLMSG_ERROR)
                    return 1;
                continue;
            }
            if (header->nlmsg_type != expected ||
                header->nlmsg_len < NLMSG_LENGTH (sizeof (*state)))
                return reply_error (error, "unexpected reply", EPROTO);
            memcpy (state, NLMSG_DATA (header), sizeof (*state));
            return 1;
        }
        if (length)
            return reply_error (error, "truncated message", EPROTO);
    }
}

static gint
exchange (MMMtkIpsec *self, guint16 type, const void *payload, gsize size,
          struct xfrm_usersa_info *state, GError **error)
{
    g_autofree struct nlmsghdr *header = g_malloc0 (NLMSG_SPACE (size));
    struct sockaddr_nl kernel = { 0 };
    ssize_t n;

    header->nlmsg_len = NLMSG_LENGTH (size);
    header->nlmsg_type = type;
    header->nlmsg_flags = NLM_F_REQUEST | (type == XFRM_MSG_DELSA ? NLM_F_ACK : 0);
    header->nlmsg_seq = ++self->sequence;
    memcpy (NLMSG_DATA (header), payload, size);
    kernel.nl_family = AF_NETLINK;
    do {
        n = sendto (self->fd, header, header->nlmsg_len, 0,
                    (struct sockaddr *) &kernel, sizeof (kernel));
    } while (n < 0 && errno == EINTR);
    if (n != header->nlmsg_len) {
        ipsec_error (error, "sendto", n < 0 ? errno : EIO);
        return -1;
    }
    return receive_reply (self, header->nlmsg_seq,
                          type == XFRM_MSG_DELSA ? NLMSG_ERROR : XFRM_MSG_NEWSA,
                          state, TRUE, error);
}

MMMtkIpsec *
mm_mtk_ipsec_new (GError **error)
{
    MMMtkIpsec *self;
    struct sockaddr_nl address = { 0 };
    gint fd;

    fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_XFRM);
    if (fd < 0) {
        ipsec_error (error, "socket", errno);
        return NULL;
    }
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1U << (XFRMNLGRP_EXPIRE - 1);
    if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0) {
        ipsec_error (error, "bind EXPIRE", errno);
        close (fd);
        return NULL;
    }
    self = g_new0 (MMMtkIpsec, 1);
    self->fd = fd;
    self->reservations = g_array_new (FALSE, FALSE, sizeof (SpiReservation));
    return self;
}

gint
mm_mtk_ipsec_fd (MMMtkIpsec *self)
{
    return self->fd;
}

static guint32
allocate_owned (MMMtkIpsec *self, SpiReservation *owned, gboolean renew, GError **error)
{
    struct xfrm_userspi_info query = { 0 };
    struct xfrm_usersa_info state = { 0 };
    guint32 spi;

    query.info.family = owned->request.address_len == 4 ? AF_INET : AF_INET6;
    query.info.id.proto = owned->request.protocol;
    query.info.mode = owned->request.mode;
    query.info.reqid = owned->reqid;
    memcpy (&query.info.saddr, owned->request.source, owned->request.address_len);
    memcpy (&query.info.id.daddr, owned->request.destination, owned->request.address_len);
    /* Linux expects host-order bounds, but the SPI in the reply is network order. */
    query.min = renew ? owned->spi : owned->request.min_spi;
    query.max = renew ? owned->spi : owned->request.max_spi;
    if (exchange (self, XFRM_MSG_ALLOCSPI, &query, sizeof (query), &state, error) != 1)
        return 0;
    spi = ntohl (state.id.spi);
    if (spi < query.min || spi > query.max || state.reqid != owned->reqid ||
        state.family != query.info.family || state.id.proto != query.info.id.proto ||
        memcmp (&state.id.daddr, &query.info.id.daddr, sizeof (state.id.daddr)) != 0) {
        ipsec_error (error, "invalid allocated SPI", EPROTO);
        return 0;
    }
    owned->spi = spi;
    owned->expired = FALSE;
    return spi;
}

static void
state_id (const SpiReservation *owned, struct xfrm_usersa_id *query)
{
    memset (query, 0, sizeof (*query));
    query->family = owned->request.address_len == 4 ? AF_INET : AF_INET6;
    query->proto = owned->request.protocol;
    query->spi = htonl (owned->spi);
    memcpy (&query->daddr, owned->request.destination, owned->request.address_len);
}

static gint
lookup_owned (MMMtkIpsec *self, SpiReservation *owned, GError **error)
{
    struct xfrm_usersa_id query;
    struct xfrm_usersa_info state = { 0 };
    gint result;

    state_id (owned, &query);
    result = exchange (self, XFRM_MSG_GETSA, &query, sizeof (query), &state, error);
    if (result == -ENOENT || result == -ESRCH) {
        g_clear_error (error);
        return 0;
    }
    if (result != 1)
        return result;
    if (state.reqid != owned->reqid)
        return reply_error (error, "state no longer owned", EPERM);
    return 1;
}

guint32
mm_mtk_ipsec_allocate (MMMtkIpsec *self, const MMMtkMipcSpiRequest *request, GError **error)
{
    SpiReservation owned = { 0 };
    guint i;

    if (request->action != MM_MTK_MIPC_SPI_ALLOC ||
        (request->address_len != 4 && request->address_len != 16) ||
        (request->protocol != 50 && request->protocol != 51) || request->mode > 1 ||
        request->min_spi < 256 || request->min_spi > request->max_spi) {
        ipsec_error (error, "invalid allocation", EINVAL);
        return 0;
    }
    for (i = 0; i < self->reservations->len; i++) {
        SpiReservation *previous = &g_array_index (self->reservations, SpiReservation, i);

        if (previous->request.transaction_id == request->transaction_id) {
            gint result;

            if (memcmp (&previous->request, request, sizeof (*request)) != 0) {
                ipsec_error (error, "transaction reused with different request", EINVAL);
                return 0;
            }
            /* ALLOCSPI without an acquire sequence deliberately ignores states
             * with a nonzero SPI. Verify the existing SA before returning it. */
            result = lookup_owned (self, previous, error);
            if (result < 0)
                return 0;
            if (result == 1)
                return previous->spi;
            return allocate_owned (self, previous, TRUE, error);
        }
    }
    if (self->reservations->len >= SPI_RESERVATION_LIMIT) {
        ipsec_error (error, "reservation limit", ENOSPC);
        return 0;
    }
    owned.request = *request;
    /* This is an ownership identifier, not a fabricated SPI. */
    owned.reqid = g_random_int ();
    if (!owned.reqid)
        owned.reqid = 1;
    if (!allocate_owned (self, &owned, FALSE, error))
        return 0;
    g_array_append_val (self->reservations, owned);
    return owned.spi;
}

static gboolean
delete_owned (MMMtkIpsec *self, SpiReservation *owned, GError **error)
{
    struct xfrm_usersa_id query;
    gint result;

    result = lookup_owned (self, owned, error);
    if (result == 0)
        return TRUE;
    if (result != 1)
        return FALSE;
    state_id (owned, &query);
    result = exchange (self, XFRM_MSG_DELSA, &query, sizeof (query), NULL, error);
    if (result == -ENOENT || result == -ESRCH) {
        g_clear_error (error);
        return TRUE;
    }
    return result == 1;
}

gboolean
mm_mtk_ipsec_release (MMMtkIpsec *self, const MMMtkMipcSpiRequest *request, GError **error)
{
    guint i;

    if (request->action != MM_MTK_MIPC_SPI_FREE ||
        (request->address_len != 4 && request->address_len != 16))
        return ipsec_error (error, "invalid release", EINVAL);
    for (i = 0; i < self->reservations->len; i++) {
        SpiReservation *owned = &g_array_index (self->reservations, SpiReservation, i);

        if (owned->spi != request->spi || owned->request.protocol != request->protocol ||
            owned->request.address_len != request->address_len ||
            memcmp (owned->request.source, request->source, request->address_len) != 0 ||
            memcmp (owned->request.destination, request->destination, request->address_len) != 0)
            continue;
        if (!delete_owned (self, owned, error))
            return FALSE;
        g_array_remove_index (self->reservations, i);
        return TRUE;
    }
    return ipsec_error (error, "unknown reservation", ENOENT);
}

gboolean
mm_mtk_ipsec_renew (MMMtkIpsec *self, GError **error)
{
    guint i;

    if (receive_reply (self, 0, 0, NULL, FALSE, error) < 0)
        return FALSE;
    for (i = 0; i < self->reservations->len; i++) {
        SpiReservation *owned = &g_array_index (self->reservations, SpiReservation, i);

        if (owned->expired && !allocate_owned (self, owned, TRUE, error))
            return FALSE;
    }
    return TRUE;
}

void
mm_mtk_ipsec_free (MMMtkIpsec *self)
{
    guint i;

    if (!self)
        return;
    for (i = 0; i < self->reservations->len; i++) {
        g_autoptr(GError) error = NULL;

        if (!delete_owned (self, &g_array_index (self->reservations, SpiReservation, i), &error))
            g_warning ("mtk-soc: XFRM cleanup failed: %s", error->message);
    }
    close (self->fd);
    g_array_unref (self->reservations);
    g_free (self);
}
