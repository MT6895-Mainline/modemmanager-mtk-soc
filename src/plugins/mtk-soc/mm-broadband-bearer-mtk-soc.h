/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MM_BROADBAND_BEARER_MTK_SOC_H
#define MM_BROADBAND_BEARER_MTK_SOC_H

#include "mm-broadband-bearer.h"

#define MM_TYPE_BROADBAND_BEARER_MTK_SOC            (mm_broadband_bearer_mtk_soc_get_type ())
#define MM_BROADBAND_BEARER_MTK_SOC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BROADBAND_BEARER_MTK_SOC, MMBroadbandBearerMtkSoc))
#define MM_BROADBAND_BEARER_MTK_SOC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_BROADBAND_BEARER_MTK_SOC, MMBroadbandBearerMtkSocClass))
#define MM_IS_BROADBAND_BEARER_MTK_SOC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BROADBAND_BEARER_MTK_SOC))
#define MM_IS_BROADBAND_BEARER_MTK_SOC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_BROADBAND_BEARER_MTK_SOC))
#define MM_BROADBAND_BEARER_MTK_SOC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_BROADBAND_BEARER_MTK_SOC, MMBroadbandBearerMtkSocClass))

typedef struct _MMBroadbandBearerMtkSoc        MMBroadbandBearerMtkSoc;
typedef struct _MMBroadbandBearerMtkSocClass   MMBroadbandBearerMtkSocClass;
typedef struct _MMBroadbandBearerMtkSocPrivate MMBroadbandBearerMtkSocPrivate;

struct _MMBroadbandBearerMtkSoc {
    MMBroadbandBearer parent;
};

struct _MMBroadbandBearerMtkSocClass {
    MMBroadbandBearerClass parent;
};

GType mm_broadband_bearer_mtk_soc_get_type (void);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (MMBroadbandBearerMtkSoc, g_object_unref)

#endif /* MM_BROADBAND_BEARER_MTK_SOC_H */
