/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "mm-mtk-ipsec.h"

#include <poll.h>
#include <string.h>

static void
test_kernel_reservations (void)
{
    MMMtkIpsec *service;
    MMMtkMipcSpiRequest first = { 0 };
    MMMtkMipcSpiRequest second;
    MMMtkMipcSpiRequest release;
    g_autoptr(GError) error = NULL;
    guint32 spi;
    guint32 other;
    struct pollfd pfd;
    gint64 started;

    if (g_strcmp0 (g_getenv ("QQC_XFRM_INTEGRATION"), "1") != 0) {
        g_test_skip ("Requires an explicitly enabled NET_ADMIN kernel test");
        return;
    }
    service = mm_mtk_ipsec_new (&error);
    g_assert_no_error (error);
    g_assert_nonnull (service);
    first.transaction_id = 0x111;
    first.address_len = 4;
    first.protocol = 50;
    first.min_spi = 0x51000000;
    first.max_spi = 0x510000ff;
    memcpy (first.destination, "\xc0\x00\x02\x01", 4);
    spi = mm_mtk_ipsec_allocate (service, &first, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (spi, >=, first.min_spi);
    g_assert_cmpuint (spi, <=, first.max_spi);
    g_assert_cmpuint (mm_mtk_ipsec_allocate (service, &first, &error), ==, spi);
    g_assert_no_error (error);
    second = first;
    second.transaction_id++;
    second.address_len = 16;
    memset (second.destination, 0, sizeof (second.destination));
    memcpy (second.destination, "\x20\x01\x0d\xb8", 4);
    second.destination[15] = 1;
    other = mm_mtk_ipsec_allocate (service, &second, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (other, >=, second.min_spi);
    g_assert_cmpuint (other, <=, second.max_spi);
    release = second;
    release.action = MM_MTK_MIPC_SPI_FREE;
    release.spi = other;
    g_assert_true (mm_mtk_ipsec_release (service, &release, &error));
    g_assert_no_error (error);
    g_assert_false (mm_mtk_ipsec_release (service, &release, &error));
    g_assert_nonnull (error);
    g_clear_error (&error);

    started = g_get_monotonic_time ();
    pfd.fd = mm_mtk_ipsec_fd (service);
    pfd.events = POLLIN;
    pfd.revents = 0;
    g_assert_cmpint (poll (&pfd, 1, 40000), >, 0);
    g_assert_true (mm_mtk_ipsec_renew (service, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (mm_mtk_ipsec_allocate (service, &first, &error), ==, spi);
    g_assert_no_error (error);
    g_test_message ("IPv4/IPv6 allocated and freed; hard expiry renewed same SPI after %.1fs",
                    (g_get_monotonic_time () - started) / 1000000.0);
    release = first;
    release.action = MM_MTK_MIPC_SPI_FREE;
    release.spi = spi;
    g_assert_true (mm_mtk_ipsec_release (service, &release, &error));
    g_assert_no_error (error);
    mm_mtk_ipsec_free (service);
}

int
main (int argc, char **argv)
{
    g_test_init (&argc, &argv, NULL);
    g_test_add_func ("/ipsec/kernel-reservations", test_kernel_reservations);
    return g_test_run ();
}
