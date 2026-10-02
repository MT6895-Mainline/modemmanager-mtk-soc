/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MM_MTK_IPSEC_H
#define MM_MTK_IPSEC_H

#include "mm-mtk-mipc.h"

typedef struct _MMMtkIpsec MMMtkIpsec;

MMMtkIpsec *mm_mtk_ipsec_new (GError **error);
gint mm_mtk_ipsec_fd (MMMtkIpsec *self);
guint32 mm_mtk_ipsec_allocate (MMMtkIpsec *self, const MMMtkMipcSpiRequest *request,
                              GError **error);
gboolean mm_mtk_ipsec_release (MMMtkIpsec *self, const MMMtkMipcSpiRequest *request,
                               GError **error);
gboolean mm_mtk_ipsec_renew (MMMtkIpsec *self, GError **error);
void mm_mtk_ipsec_free (MMMtkIpsec *self);

#endif
