/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <gmodule.h>

#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-plugin-common.h"
#include "mm-broadband-modem-mtk-soc.h"

#define MM_TYPE_PLUGIN_MTK_SOC mm_plugin_mtk_soc_get_type ()
MM_DEFINE_PLUGIN (MTK_SOC, mtk_soc, MtkSoc)

static MMBaseModem *
create_modem (MMPlugin *self,
              const gchar *uid,
              const gchar *physdev,
              const gchar **drivers,
              guint16 vendor,
              guint16 product,
              guint16 subsystem_vendor,
              guint16 subsystem_device,
              GList *probes,
              GError **error)
{
    return MM_BASE_MODEM (mm_broadband_modem_mtk_soc_new (uid,
                                                          physdev,
                                                          drivers,
                                                          mm_plugin_get_name (self),
                                                          vendor,
                                                          product));
}

MM_PLUGIN_NAMED_CREATOR_SCOPE MMPlugin *
mm_plugin_create_mtk_soc (void)
{
    static const gchar *subsystems[] = { "tty", "net", NULL };
    static const gchar *udev_tags[] = { "ID_MM_MTK_SOC", NULL };

    return MM_PLUGIN (
        g_object_new (MM_TYPE_PLUGIN_MTK_SOC,
                      MM_PLUGIN_NAME,               MM_MODULE_NAME,
                      MM_PLUGIN_ALLOWED_SUBSYSTEMS, subsystems,
                      MM_PLUGIN_ALLOWED_UDEV_TAGS,  udev_tags,
                      MM_PLUGIN_ALLOWED_AT,         TRUE,
                      NULL));
}

static void
mm_plugin_mtk_soc_init (MMPluginMtkSoc *self)
{
}

static void
mm_plugin_mtk_soc_class_init (MMPluginMtkSocClass *klass)
{
    MM_PLUGIN_CLASS (klass)->create_modem = create_modem;
}
