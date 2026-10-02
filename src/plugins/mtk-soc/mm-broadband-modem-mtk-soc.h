/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MM_BROADBAND_MODEM_MTK_SOC_H
#define MM_BROADBAND_MODEM_MTK_SOC_H

#include "mm-broadband-modem.h"

/* Modem qdata key holding the 1-based SIM slot picked by load_sim_slots and
 * consumed by the MIPC direct-IP bearer as the first DATA_ACT candidate. */
#define MM_MTK_SOC_PRIMARY_SLOT_DATA "mm-mtk-soc-primary-slot"

#define MM_TYPE_BROADBAND_MODEM_MTK_SOC            (mm_broadband_modem_mtk_soc_get_type ())
#define MM_BROADBAND_MODEM_MTK_SOC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BROADBAND_MODEM_MTK_SOC, MMBroadbandModemMtkSoc))
#define MM_BROADBAND_MODEM_MTK_SOC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_BROADBAND_MODEM_MTK_SOC, MMBroadbandModemMtkSocClass))
#define MM_IS_BROADBAND_MODEM_MTK_SOC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BROADBAND_MODEM_MTK_SOC))
#define MM_IS_BROADBAND_MODEM_MTK_SOC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_BROADBAND_MODEM_MTK_SOC))
#define MM_BROADBAND_MODEM_MTK_SOC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_BROADBAND_MODEM_MTK_SOC, MMBroadbandModemMtkSocClass))

typedef struct _MMBroadbandModemMtkSoc      MMBroadbandModemMtkSoc;
typedef struct _MMBroadbandModemMtkSocClass MMBroadbandModemMtkSocClass;

struct _MMBroadbandModemMtkSoc {
    MMBroadbandModem parent;
};

struct _MMBroadbandModemMtkSocClass {
    MMBroadbandModemClass parent;
};

GType mm_broadband_modem_mtk_soc_get_type (void);

MMBroadbandModemMtkSoc *mm_broadband_modem_mtk_soc_new (const gchar  *device,
                                                        const gchar  *physdev,
                                                        const gchar **drivers,
                                                        const gchar  *plugin,
                                                        guint16       vendor_id,
                                                        guint16       product_id);

#endif /* MM_BROADBAND_MODEM_MTK_SOC_H */
