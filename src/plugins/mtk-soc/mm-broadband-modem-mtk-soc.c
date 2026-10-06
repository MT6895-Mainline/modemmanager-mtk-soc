/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <string.h>

#include "ModemManager.h"
#include "mm-base-modem-at.h"
#include "mm-base-sim.h"
#include "mm-broadband-bearer-mtk-soc.h"
#include "mm-broadband-modem.h"
#include "mm-broadband-modem-mtk-soc.h"
#include "mm-iface-modem.h"
#include "mm-log-object.h"
#include "mm-modem-helpers.h"
#include "mm-port-serial-at.h"

static void iface_modem_init (MMIfaceModemInterface *iface);
static void load_signal_quality (MMIfaceModem *self, GAsyncReadyCallback callback, gpointer user_data);
static guint load_signal_quality_finish (MMIfaceModem *self, GAsyncResult *res, GError **error);

G_DEFINE_TYPE_EXTENDED (MMBroadbandModemMtkSoc,
                        mm_broadband_modem_mtk_soc,
                        MM_TYPE_BROADBAND_MODEM,
                        0,
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM, iface_modem_init))

typedef struct {
    GPtrArray *sim_slots;
    GTask     *task;              /* the load_sim_slots task; it owns this context */
    gchar    **slot_identifiers;  /* canonical ICCID per slot, NULL when unknown */
    guint      count;
    guint      primary_sim_slot;
} LoadSimSlotsContext;

static void sim_identifier_ready (MMBaseModem         *self,
                                  GAsyncResult        *res,
                                  LoadSimSlotsContext *ctx);

static void
load_sim_slots_context_free (LoadSimSlotsContext *ctx)
{
    g_clear_pointer (&ctx->sim_slots, g_ptr_array_unref);
    g_strfreev (ctx->slot_identifiers);
    g_free (ctx);
}

static void
sim_slot_free (MMBaseSim *sim)
{
    if (sim)
        g_object_unref (sim);
}

/* The status string is quoted and may itself contain a comma. */
static gchar **
split_eslotsinfo_fields (const gchar *line,
                         GError     **error)
{
    g_autoptr(GPtrArray) fields = NULL;
    const gchar         *p;

    fields = g_ptr_array_new_with_free_func (g_free);
    p = line;
    while (TRUE) {
        g_autoptr(GString) value = g_string_new (NULL);
        gboolean quoted;

        while (g_ascii_isspace (*p))
            p++;
        quoted = (*p == '"');
        if (quoted) {
            p++;
            while (*p) {
                if (*p == '"') {
                    if (p[1] != '"')
                        break;
                    p++;
                }
                g_string_append_c (value, *p);
                p++;
            }
            if (*p != '"')
                goto invalid;
            p++;
            while (g_ascii_isspace (*p))
                p++;
            if (*p && *p != ',')
                goto invalid;
        } else {
            while (*p && *p != ',') {
                if (*p == '"')
                    goto invalid;
                g_string_append_c (value, *p);
                p++;
            }
            g_strstrip (value->str);
        }

        g_ptr_array_add (fields, g_string_free (g_steal_pointer (&value), FALSE));
        if (!*p)
            break;
        p++;
    }

    g_ptr_array_add (fields, NULL);
    return (gchar **) g_ptr_array_free (g_steal_pointer (&fields), FALSE);

invalid:
    g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED,
                 "Invalid +ESLOTSINFO field syntax");
    return NULL;
}

static gchar **
parse_eslotsinfo (const gchar *response,
                  guint       *slot_count,
                  GError     **error)
{
    const gchar *start;
    const gchar *end;
    gchar       *line;
    gchar      **fields;
    guint        count;

    start = g_strstr_len (response, -1, "+ESLOTSINFO:");
    if (!start) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Couldn't find +ESLOTSINFO in response");
        return NULL;
    }

    start += strlen ("+ESLOTSINFO:");
    end = strpbrk (start, "\r\n");
    line = end ? g_strndup (start, end - start) : g_strdup (start);
    g_strstrip (line);

    fields = split_eslotsinfo_fields (line, error);
    g_free (line);
    if (!fields)
        return NULL;
    if (!fields[0] || !mm_get_uint_from_str (fields[0], &count) ||
        count == 0 || count > 4) {
        g_strfreev (fields);
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Invalid +ESLOTSINFO slot count");
        return NULL;
    }

    if (g_strv_length (fields) != 1 + count * 6) {
        g_strfreev (fields);
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Invalid +ESLOTSINFO field count for %u slots",
                     count);
        return NULL;
    }

    *slot_count = count;
    return fields;
}

static gboolean
slot_is_explicitly_absent (const gchar *pin_state)
{
    g_autofree gchar *upper = g_ascii_strup (pin_state, -1);
    const gchar     *code;
    guint            value;

    g_strstrip (upper);
    if (g_strrstr (upper, "NOT INSERTED") || g_strrstr (upper, "ABSENT"))
        return TRUE;

    if (!g_str_has_prefix (upper, "+CME ERROR:"))
        return FALSE;

    code = upper + strlen ("+CME ERROR:");
    while (g_ascii_isspace (*code))
        code++;
    return mm_get_uint_from_str (code, &value) &&
           value == MM_MOBILE_EQUIPMENT_ERROR_SIM_NOT_INSERTED;
}

static gboolean
slot_is_ready (const gchar *pin_state)
{
    g_autofree gchar *upper = g_ascii_strup (pin_state, -1);

    return g_str_has_prefix (upper, "+CPIN: READY");
}

static void
eslotsinfo_query_ready (MMBaseModem  *self,
                        GAsyncResult *res,
                        GTask        *task)
{
    LoadSimSlotsContext *ctx;
    const gchar          *response;
    g_autoptr(GError)     error = NULL;
    g_auto(GStrv)         fields = NULL;
    guint                 count;
    guint                 i;
    guint                 first_present = 0;
    guint                 logical_zero = 0;
    guint                 first_ready = 0;
    guint                 ready_logical_zero = 0;

    ctx = g_task_get_task_data (task);
    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        if (!error)
            g_set_error (&error,
                         MM_CORE_ERROR,
                         MM_CORE_ERROR_FAILED,
                         "No response to +ESLOTSINFO?");
        g_task_return_error (task, g_steal_pointer (&error));
        g_object_unref (task);
        return;
    }

    fields = parse_eslotsinfo (response, &count, &error);
    if (!fields) {
        g_task_return_error (task, g_steal_pointer (&error));
        g_object_unref (task);
        return;
    }

    ctx->count = count;
    ctx->slot_identifiers = g_new0 (gchar *, count + 1);
    ctx->sim_slots = g_ptr_array_new_with_free_func ((GDestroyNotify) sim_slot_free);
    for (i = 0; i < count; i++) {
        const guint base = 1 + i * 6;
        g_autofree gchar *sim_identifier = NULL;
        g_autoptr(GError) iccid_error = NULL;
        const gchar *pin_state = fields[base];
        const gchar *eid = fields[base + 4];
        const gchar *iccid = fields[base + 5];
        gint logical_slot;
        guint slot_state;
        MMBaseSim *sim = NULL;

        if (!mm_get_uint_from_str (fields[base + 1], &slot_state) ||
            !mm_get_int_from_str (fields[base + 2], &logical_slot) ||
            slot_state > 1 || logical_slot < -1 || logical_slot > 3) {
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "Invalid +ESLOTSINFO slot mapping for slot %u",
                                     i + 1);
            g_object_unref (task);
            return;
        }

        /*
         * A busy or otherwise unknown SIM is still a physical slot. Only an
         * explicit absent status is left as NULL, so MM doesn't erase a card
         * merely because the modem is still initializing it.
         */
        if (!slot_is_explicitly_absent (pin_state)) {
            if (iccid[0])
                sim_identifier = mm_3gpp_parse_iccid (iccid, &iccid_error);
            if (iccid_error)
                mm_obj_warn (self, "couldn't parse ICCID in SIM slot %u", i + 1);
            if (sim_identifier)
                ctx->slot_identifiers[i] = g_strdup (sim_identifier);

            sim = mm_base_sim_new_initialized (self,
                                               i + 1,
                                               FALSE,
                                               sim_identifier,
                                               NULL,
                                               eid[0] ? eid : NULL,
                                               NULL,
                                               NULL,
                                               NULL);
            if (!first_present)
                first_present = i + 1;
            if (!logical_zero && logical_slot == 0)
                logical_zero = i + 1;
            if (slot_is_ready (pin_state)) {
                if (!first_ready)
                    first_ready = i + 1;
                if (!ready_logical_zero && logical_slot == 0)
                    ready_logical_zero = i + 1;
            }
        }

        g_ptr_array_add (ctx->sim_slots, sim);
    }

    /* Fallback choice, used when the modem's active ICCID cannot be matched
     * against +ESLOTSINFO. A busy mapped slot need not be the card currently
     * usable by radio. */
    ctx->primary_sim_slot = ready_logical_zero ? ready_logical_zero :
                            first_ready ? first_ready :
                            logical_zero ? logical_zero :
                            first_present ? first_present : 1;

    /* The plain AT commands address exactly one SIM - the modem's "major" SIM -
     * and it is NOT necessarily the slot whose +ESLOTSINFO logical index is 0:
     * on the PGZ110 the card in the second tray is the major one, even after
     * AT+EFUN=3 powers both slots and even after a CFUN=0/CFUN=1 cycle.
     * Asking the modem for that ICCID and matching it against the per-slot
     * ICCIDs is the only deterministic way to publish the right slot as
     * "active". Publishing the wrong one makes ModemManager see a SIM swap on
     * every probe (mm_iface_modem_process_sim_event) and reprobe forever. */
    mm_base_modem_at_command (MM_BASE_MODEM (self), "AT+CRSM=176,12258,0,0,10", 5, FALSE,
                              (GAsyncReadyCallback) sim_identifier_ready, ctx);
}

static void
sim_identifier_ready (MMBaseModem         *self,
                      GAsyncResult        *res,
                      LoadSimSlotsContext *ctx)
{
    g_autoptr(GError) error = NULL;
    g_autofree gchar *active = NULL;
    const gchar      *response;
    const gchar      *open_quote;
    const gchar      *close_quote;
    guint             i;
    guint             matched = 0;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response)
        mm_obj_dbg (self, "couldn't read the active SIM ICCID: %s", error->message);
    else {
        open_quote = strchr (response, '"');
        close_quote = open_quote ? strchr (open_quote + 1, '"') : NULL;
        if (open_quote && close_quote && close_quote > open_quote + 1)
            active = mm_3gpp_parse_iccid (open_quote + 1, NULL);
    }

    if (active) {
        for (i = 0; i < ctx->count; i++) {
            if (ctx->slot_identifiers[i] &&
                g_strcmp0 (ctx->slot_identifiers[i], active) == 0) {
                matched = i + 1;
                break;
            }
        }
    }

    if (matched) {
        ctx->primary_sim_slot = matched;
        mm_obj_info (self, "the modem's AT commands address SIM slot %u", matched);
    } else
        mm_obj_info (self,
                     "couldn't match the active SIM ICCID; keeping slot %u as primary",
                     ctx->primary_sim_slot);

    if (g_ptr_array_index (ctx->sim_slots, ctx->primary_sim_slot - 1))
        g_object_set (g_ptr_array_index (ctx->sim_slots, ctx->primary_sim_slot - 1),
                      "active",
                      TRUE,
                      NULL);

    mm_obj_info (self, "+ESLOTSINFO reported %u SIM slots (primary %u)",
                 ctx->count, ctx->primary_sim_slot);
    g_task_return_boolean (ctx->task, TRUE);
    /* ctx is owned by the task and is released with it. */
    g_object_unref (ctx->task);
}

static gboolean
load_sim_slots_finish (MMIfaceModem  *self,
                       GAsyncResult *res,
                       GPtrArray   **sim_slots,
                       guint        *primary_sim_slot,
                       GError      **error)
{
    LoadSimSlotsContext *ctx;

    if (!g_task_propagate_boolean (G_TASK (res), error))
        return FALSE;

    ctx = g_task_get_task_data (G_TASK (res));
    if (sim_slots)
        *sim_slots = g_steal_pointer (&ctx->sim_slots);
    if (primary_sim_slot)
        *primary_sim_slot = ctx->primary_sim_slot;

    /* The MIPC bearer reads this back to pick the first DATA_ACT slot. */
    g_object_set_data (G_OBJECT (self),
                       MM_MTK_SOC_PRIMARY_SLOT_DATA,
                       GUINT_TO_POINTER (ctx->primary_sim_slot));
    return TRUE;
}

static void
load_sim_slots (MMIfaceModem       *self,
                GAsyncReadyCallback callback,
                gpointer            user_data)
{
    GTask *task;
    LoadSimSlotsContext *ctx;

    task = g_task_new (self, NULL, callback, user_data);
    ctx = g_new0 (LoadSimSlotsContext, 1);
    ctx->task = task;
    g_task_set_task_data (task, ctx, (GDestroyNotify) load_sim_slots_context_free);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+ESLOTSINFO?",
                              10,
                              FALSE,
                              (GAsyncReadyCallback) eslotsinfo_query_ready,
                              task);
}

/*****************************************************************************/
/* Bearer creation.                                                           */
/*                                                                            */
/* The MEDIATEK MD exposes direct-IP data calls over CCCI/MIPC, not over the   */
/* AT/PPP path, so every bearer is the MIPC one.  Construction is synchronous  */
/* (no GAsyncInitable init), because the connection itself opens and drives    */
/* /dev/ttyCMIPC1 from its own worker thread and never touches the AT port.    */

static MMBaseBearer *
create_bearer_finish (MMIfaceModem *self,
                      GAsyncResult *res,
                      GError      **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
create_bearer (MMIfaceModem        *self,
               MMBearerProperties  *properties,
               GAsyncReadyCallback  callback,
               gpointer             user_data)
{
    GTask         *task;
    MMBaseBearer  *bearer;

    task = g_task_new (self, NULL, callback, user_data);

    bearer = MM_BASE_BEARER (g_object_new (MM_TYPE_BROADBAND_BEARER_MTK_SOC,
                                           MM_BASE_BEARER_MODEM, self,
                                           MM_BASE_BEARER_CONFIG, properties,
                                           NULL));
    mm_base_bearer_export (bearer);
    g_task_return_pointer (task, bearer, g_object_unref);
    g_object_unref (task);
}

/*****************************************************************************/
/* Primary SIM slot switching (AT+ESIMMAP)                                    */
/*                                                                            */
/* MTK's "major SIM" is the card that owns the modem's main protocol stack;    */
/* AT+ESIMMAP selects it as a BITMASK (1 << slot_index, slot_index 0-based).   */
/* That semantics comes from the stock RIL:                                    */
/* RmcCapabilitySwitchRequestHandler::requestSetRadioCapability (0x3a95dc)     */
/* does `lsl w1, w9, w8` at 0x3a98ec before formatting "AT+ESIMMAP=%d".        */
/* The value persists in SBP NVRAM across reboots.                             */
/*                                                                            */
/* ModemManager's sim_slot is 1-based.  On success MM calls                    */
/* mm_iface_modem_process_sim_event(), which disables and reprobes the modem,  */
/* so load_sim_slots() re-matches the active ICCID and republishes which SIM   */
/* object is active.                                                           */
/*                                                                            */
/* The structure deliberately mirrors the Cinterion AT plugin: the GTask is    */
/* the AT callback data and is the only object this request owns, so the       */
/* lifetime is trivial.  (An earlier three-command variant kept its own context */
/* that unreffed the task from inside the completion path, and ModemManager     */
/* crashed with SIGSEGV in that callback - see run25.md §17.)                  */

typedef struct {
    guint sim_slot;   /* 1-based, as requested by ModemManager */
} SetPrimarySimSlotContext;

static void
set_primary_sim_slot_context_free (SetPrimarySimSlotContext *ctx)
{
    g_slice_free (SetPrimarySimSlotContext, ctx);
}

static void
set_primary_sim_slot_ready (MMBaseModem  *self,
                            GAsyncResult *res,
                            GTask        *task)
{
    GError                   *error = NULL;
    SetPrimarySimSlotContext *ctx;

    ctx = g_task_get_task_data (task);

    if (!mm_base_modem_at_command_finish (self, res, &error)) {
        if (!error)
            error = g_error_new_literal (MM_CORE_ERROR, MM_CORE_ERROR_FAILED,
                                         "AT+ESIMMAP did not complete");
        g_task_return_error (task, error);   /* takes ownership of the error */
    } else {
        mm_obj_info (self, "requested primary SIM slot %u (AT+ESIMMAP=0x%x)",
                     ctx->sim_slot, 1u << (ctx->sim_slot - 1));
        g_task_return_boolean (task, TRUE);
    }

    g_object_unref (task);
}

static void
set_primary_sim_slot (MMIfaceModem        *self,
                      guint                sim_slot,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data)
{
    GTask                    *task;
    g_autofree gchar         *cmd = NULL;
    SetPrimarySimSlotContext *ctx;

    task = g_task_new (self, NULL, callback, user_data);

    if (sim_slot < 1 || sim_slot > 4) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                                 "invalid SIM slot %u", sim_slot);
        g_object_unref (task);
        return;
    }

    ctx = g_slice_new0 (SetPrimarySimSlotContext);
    ctx->sim_slot = sim_slot;
    g_task_set_task_data (task, ctx, (GDestroyNotify) set_primary_sim_slot_context_free);

    cmd = g_strdup_printf ("AT+ESIMMAP=%u", 1u << (sim_slot - 1));
    mm_base_modem_at_command (MM_BASE_MODEM (self), cmd, 10, FALSE,
                              (GAsyncReadyCallback) set_primary_sim_slot_ready, task);
}

static gboolean
set_primary_sim_slot_finish (MMIfaceModem  *self,
                             GAsyncResult  *res,
                             GError       **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

/*****************************************************************************/
/* Capabilities.                                                              */
/*                                                                            */
/* The MD is a 5G-capable part: the firmware is MOLY.NR16.R1.MP1MP2.TC16...,   */
/* and the modem really does attach to NR -- AT+COPS reports <AcT>=11 ("NR      */
/* connected to 5GCN", 3GPP TS 27.007) and ModemManager itself shows access     */
/* tech 5gnr.  MMBroadbandModem's default only advertises GSM/UMTS + LTE, so    */
/* mmcli printed "supported: gsm-umts, lte" while the modem sat on 5G, and any  */
/* VoNR decision taken from CurrentCapabilities was wrong.  Report the real     */
/* set.  (The mode list already allowed 5g, so this only makes the two agree.)  */
/*****************************************************************************/

static void
load_supported_capabilities (MMIfaceModem       *self,
                             GAsyncReadyCallback callback,
                             gpointer            user_data)
{
    GArray            *capabilities;
    MMModemCapability  value;
    GTask             *task;

    /* SupportedCapabilities is a list of capability *combinations* that can be
     * used simultaneously, so this is ONE element holding the OR of the set --
     * not one element per capability.  (Appending them separately made mmcli
     * print the bogus "supported: gsm-umts".) */
    capabilities = g_array_sized_new (FALSE, FALSE, sizeof (MMModemCapability), 1);

    value = (MM_MODEM_CAPABILITY_GSM_UMTS |
             MM_MODEM_CAPABILITY_LTE |
             MM_MODEM_CAPABILITY_5GNR);
    g_array_append_val (capabilities, value);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_pointer (task, capabilities, (GDestroyNotify) g_array_unref);
    g_object_unref (task);
}

static GArray *
load_supported_capabilities_finish (MMIfaceModem  *self,
                                    GAsyncResult  *res,
                                    GError       **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
load_current_capabilities (MMIfaceModem       *self,
                           GAsyncReadyCallback callback,
                           gpointer            user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_int (task,
                       (MM_MODEM_CAPABILITY_GSM_UMTS |
                        MM_MODEM_CAPABILITY_LTE |
                        MM_MODEM_CAPABILITY_5GNR));
    g_object_unref (task);
}

static MMModemCapability
load_current_capabilities_finish (MMIfaceModem  *self,
                                  GAsyncResult  *res,
                                  GError       **error)
{
    return (MMModemCapability) g_task_propagate_int (G_TASK (res), error);
}

/*****************************************************************************/
/* Manufacturer and model (Modem interface)                                   */
/*                                                                            */
/* The MD answers AT+CGMI with "MTK1" and AT+CGMM with "MTK2".  Those are      */
/* firmware placeholders, so report the actual silicon name instead.  Both     */
/* strings stay overridable through MTK_CCCI_MANUFACTURER / MTK_CCCI_MODEL,    */
/* which is also how a different MediaTek part can be described without        */
/* touching the source.                                                       */

#define MTK_SOC_DEFAULT_MANUFACTURER "MediaTek"
#define MTK_SOC_DEFAULT_MODEL        "MediaTek M80"

static const gchar *
mtk_soc_identity (const gchar *env, const gchar *fallback)
{
    const gchar *value;

    value = g_getenv (env);
    return (value && *value) ? value : fallback;
}

static gchar *
modem_load_manufacturer_finish (MMIfaceModem *self,
                                GAsyncResult *res,
                                GError      **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
modem_load_manufacturer (MMIfaceModem       *self,
                         GAsyncReadyCallback callback,
                         gpointer            user_data)
{
    GTask       *task;
    const gchar *value;

    value = mtk_soc_identity ("MTK_CCCI_MANUFACTURER", MTK_SOC_DEFAULT_MANUFACTURER);
    mm_obj_dbg (self, "reporting manufacturer '%s'", value);
    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_pointer (task, g_strdup (value), g_free);
    g_object_unref (task);
}

static gchar *
modem_load_model_finish (MMIfaceModem *self,
                         GAsyncResult *res,
                         GError      **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
modem_load_model (MMIfaceModem       *self,
                  GAsyncReadyCallback callback,
                  gpointer            user_data)
{
    GTask       *task;
    const gchar *value;

    value = mtk_soc_identity ("MTK_CCCI_MODEL", MTK_SOC_DEFAULT_MODEL);
    mm_obj_dbg (self, "reporting model '%s'", value);
    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_pointer (task, g_strdup (value), g_free);
    g_object_unref (task);
}

/*****************************************************************************/
/* Modem modes: MediaTek AT+ERAT.                                            */
/*                                                                           */
/* The plugin did not implement set_current_modes, so the UI reported         */
/* "Setting allowed modes not supported" even though the MD supports 2G/3G/   */
/* 4G/5G.  AT+ERAT takes a bitmap (range 0-30) and AT+ERAT? answers           */
/*   "+ERAT: <current>,<x>,<setting>,<y>,<z>"                                 */
/* Measured on pearl:                                                         */
/*   AT+ERAT=7  2G/3G/4G (the value the factory left behind in the OSS drop)  */
/*   AT+ERAT=15 adds 5G NR - verified, access tech became 5gnr                */
/*   AT+ERAT=22 factory value, LTE                                            */
/*   AT+ERAT=8  +CME ERROR: 4, NR alone is rejected: it needs an LTE anchor   */
/* so the bits are 1=2G, 2=3G, 4=4G, 8=5G.                                    */
/*****************************************************************************/

#define MTK_SOC_ERAT_2G 0x01
#define MTK_SOC_ERAT_3G 0x02
#define MTK_SOC_ERAT_4G 0x04
#define MTK_SOC_ERAT_5G 0x08

#define MTK_SOC_ALL_MODES \
    (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G | MM_MODEM_MODE_5G)

static MMModemMode
mtk_soc_erat_to_modes (guint erat)
{
    MMModemMode modes = MM_MODEM_MODE_NONE;

    if (erat & MTK_SOC_ERAT_2G)
        modes |= MM_MODEM_MODE_2G;
    if (erat & MTK_SOC_ERAT_3G)
        modes |= MM_MODEM_MODE_3G;
    if (erat & MTK_SOC_ERAT_4G)
        modes |= MM_MODEM_MODE_4G;
    if (erat & MTK_SOC_ERAT_5G)
        modes |= MM_MODEM_MODE_5G;
    return modes;
}

static guint
mtk_soc_modes_to_erat (MMModemMode modes)
{
    guint erat = 0;

    if (modes & MM_MODEM_MODE_2G)
        erat |= MTK_SOC_ERAT_2G;
    if (modes & MM_MODEM_MODE_3G)
        erat |= MTK_SOC_ERAT_3G;
    if (modes & MM_MODEM_MODE_4G)
        erat |= MTK_SOC_ERAT_4G;
    if (modes & MM_MODEM_MODE_5G) {
        erat |= MTK_SOC_ERAT_5G;

        /* Measured on pearl: the MD only accepts a bitmap that keeps the GSM
         * bit when NR is enabled - AT+ERAT=8, 12 and 14 all answer
         * "+CME ERROR: 4", while 15 is accepted and the modem then camps on
         * 5G NR.  So asking for 5G means asking for the whole bitmap; the
         * modem picks NR by itself when the network offers it. */
        erat |= MTK_SOC_ERAT_2G | MTK_SOC_ERAT_3G | MTK_SOC_ERAT_4G;
    }

    return erat;
}

/* Supported modes */

/* ModemManager only lets a client set a combination that the plugin listed as
 * supported ("Cannot change modes: only one combination supported" otherwise),
 * so the list below has to contain every set the UI may ask for. */
static const MMModemMode mtk_soc_supported_mode_combinations[] = {
    MM_MODEM_MODE_2G,
    MM_MODEM_MODE_3G,
    MM_MODEM_MODE_4G,
    MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
    MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
    /* 2G+3G+4G (AT+ERAT=7) is answered with a CME error by this firmware, so
     * it is not offered either.  Only the full bitmap can enable NR (see
     * mtk_soc_modes_to_erat), so
     * "5G" and "4G+5G" are deliberately absent: the MD rejects those bitmaps
     * and ModemManager would then report a mismatch between the requested and
     * the reloaded modes.  Picking the full set is how 5G is selected. */
    MTK_SOC_ALL_MODES,
};

static void
modem_load_supported_modes (MMIfaceModem        *self,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static GArray *
modem_load_supported_modes_finish (MMIfaceModem  *self,
                                   GAsyncResult  *res,
                                   GError       **error)
{
    GArray *modes;
    guint   i;

    if (!g_task_propagate_boolean (G_TASK (res), error))
        return NULL;

    modes = g_array_sized_new (FALSE, FALSE, sizeof (MMModemModeCombination),
                               G_N_ELEMENTS (mtk_soc_supported_mode_combinations));
    for (i = 0; i < G_N_ELEMENTS (mtk_soc_supported_mode_combinations); i++) {
        MMModemModeCombination mode;

        mode.allowed = mtk_soc_supported_mode_combinations[i];
        mode.preferred = MM_MODEM_MODE_NONE;
        g_array_append_val (modes, mode);
    }

    return modes;
}

/* Current modes */

static void
current_modes_ready (MMBaseModem  *self,
                     GAsyncResult *res,
                     GTask        *task)
{
    g_autoptr(GError)  error = NULL;
    const gchar  *response = NULL;
    g_auto(GStrv)      split = NULL;
    guint              erat;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        g_task_return_error (task, g_steal_pointer (&error));
        g_object_unref (task);
        return;
    }

    /* "+ERAT: 11,0,15,0,0" - the third field is the configured bitmap */
    split = g_strsplit (response, ",", -1);
    if (g_strv_length (split) < 3) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_FAILED,
                                 "Unexpected AT+ERAT? response: %s", response);
        g_object_unref (task);
        return;
    }

    erat = (guint) g_ascii_strtoull (g_strstrip (split[2]), NULL, 10);
    mm_obj_dbg (self, "AT+ERAT? reports bitmap 0x%x", erat);
    g_task_return_int (task, (gssize) mtk_soc_erat_to_modes (erat));
    g_object_unref (task);
}

static void
modem_load_current_modes (MMIfaceModem        *self,
                          GAsyncReadyCallback  callback,
                          gpointer             user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);
    mm_base_modem_at_command (MM_BASE_MODEM (self), "AT+ERAT?", 3, FALSE,
                              (GAsyncReadyCallback) current_modes_ready, task);
}

static gboolean
modem_load_current_modes_finish (MMIfaceModem  *self,
                                 GAsyncResult  *res,
                                 MMModemMode   *allowed,
                                 MMModemMode   *preferred,
                                 GError       **error)
{
    GError *inner_error = NULL;
    gssize  value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return FALSE;
    }

    *allowed = (MMModemMode) value;
    *preferred = MM_MODEM_MODE_NONE;
    return TRUE;
}

/* Set current modes */

static void
set_current_modes_ready (MMBaseModem  *self,
                         GAsyncResult *res,
                         GTask        *task)
{
    g_autoptr(GError) error = NULL;
    const gchar *response = NULL;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        g_task_return_error (task, g_steal_pointer (&error));
        g_object_unref (task);
        return;
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_set_current_modes (MMIfaceModem        *self,
                         MMModemMode          modes,
                         MMModemMode          preferred,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data)
{
    GTask             *task;
    g_autofree gchar  *command = NULL;
    guint              erat;

    task = g_task_new (self, NULL, callback, user_data);

    if (preferred != MM_MODEM_MODE_NONE && preferred != modes) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
                                 "Preferred mode is not supported by AT+ERAT");
        g_object_unref (task);
        return;
    }

    erat = mtk_soc_modes_to_erat (modes);
    command = g_strdup_printf ("AT+ERAT=%u", erat);
    mm_obj_info (self, "setting allowed modes 0x%x -> %s", modes, command);

    mm_base_modem_at_command (MM_BASE_MODEM (self), command, 5, FALSE,
                              (GAsyncReadyCallback) set_current_modes_ready, task);
}

static gboolean
modem_set_current_modes_finish (MMIfaceModem  *self,
                                GAsyncResult  *res,
                                GError       **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
iface_modem_init (MMIfaceModemInterface *iface)
{
    iface->load_manufacturer = modem_load_manufacturer;
    iface->load_manufacturer_finish = modem_load_manufacturer_finish;
    iface->load_model = modem_load_model;
    iface->load_model_finish = modem_load_model_finish;
    iface->load_sim_slots = load_sim_slots;
    iface->load_sim_slots_finish = load_sim_slots_finish;
    iface->set_primary_sim_slot = set_primary_sim_slot;
    iface->set_primary_sim_slot_finish = set_primary_sim_slot_finish;
    iface->load_signal_quality = load_signal_quality;
    iface->load_signal_quality_finish = load_signal_quality_finish;
    iface->create_bearer = create_bearer;
    iface->create_bearer_finish = create_bearer_finish;
    iface->load_supported_capabilities = load_supported_capabilities;
    iface->load_supported_capabilities_finish = load_supported_capabilities_finish;
    iface->load_current_capabilities = load_current_capabilities;
    iface->load_current_capabilities_finish = load_current_capabilities_finish;
    iface->load_supported_modes = modem_load_supported_modes;
    iface->load_supported_modes_finish = modem_load_supported_modes_finish;
    iface->load_current_modes = modem_load_current_modes;
    iface->load_current_modes_finish = modem_load_current_modes_finish;
    iface->set_current_modes = modem_set_current_modes;
    iface->set_current_modes_finish = modem_set_current_modes_finish;
}

/*****************************************************************************/
/* Signal quality from the MediaTek +ECSQ response.                           */
/*                                                                            */
/* MMBroadbandModem queries only AT+CSQ, and this MD answers +CSQ: 99,99       */
/* (unknown) while camped on LTE/NR, so the SignalQuality property is always   */
/* 0%.  AT+ECSQ returns one "+ECSQ: ..." line per RAT.  The stock RIL parser   */
/* (RmcNetworkHandler::getMdSignalStrengthByAT, 0x33cd40, reads 13 integers)   */
/* and its caller (RmcNetworkHandler::updateSignalStrength, 0x33cf50) use the  */
/* 6th and 7th fields divided by 4 as the LTE/NR RSRQ and RSRP in dB.  We use  */
/* the same fields and MM's MM_RSRP_TO_QUALITY macro for the percentage.       */

static gboolean
parse_ecsq_rsrp (const gchar *response,
                 gint        *out_rsrp,
                 gint        *out_rsrq)
{
    g_auto(GStrv) lines = NULL;
    guint i;

    lines = g_strsplit (response, "\n", -1);
    for (i = 0; lines[i]; i++) {
        g_autofree gchar *line = g_strdup (g_strstrip (lines[i]));
        g_auto(GStrv) fields = NULL;
        guint n;
        gint rsrq_raw, rsrp_raw;

        if (!g_str_has_prefix (line, "+ECSQ: "))
            continue;

        fields = g_strsplit (line + strlen ("+ECSQ: "), ",", -1);
        for (n = 0; fields[n]; n++)
            ;
        /* The serving-RAT line carries all 13 fields; shorter lines are for
         * RATs the modem is not using and have sentinel values. */
        if (n < 13)
            continue;
        if (!mm_get_int_from_str (g_strstrip (fields[5]), &rsrq_raw) ||
            !mm_get_int_from_str (g_strstrip (fields[6]), &rsrp_raw))
            continue;
        if (rsrp_raw == 32767 || rsrp_raw == -512 || rsrp_raw == 0)
            continue;

        *out_rsrp = rsrp_raw / 4;
        *out_rsrq = rsrq_raw / 4;
        return TRUE;
    }
    return FALSE;
}

static guint
load_signal_quality_finish (MMIfaceModem *self,
                            GAsyncResult *res,
                            GError      **error)
{
    return GPOINTER_TO_UINT (g_task_propagate_pointer (G_TASK (res), error));
}

static void
ecsq_ready (MMBaseModem  *self,
            GAsyncResult *res,
            GTask        *task)
{
    g_autoptr(GError) error = NULL;
    const gchar      *response;
    gint              rsrp = 0;
    gint              rsrq = 0;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        mm_obj_dbg (self, "couldn't query +ECSQ: %s", error->message);
        g_task_return_pointer (task, GUINT_TO_POINTER (0), NULL);
        g_object_unref (task);
        return;
    }

    if (!parse_ecsq_rsrp (response, &rsrp, &rsrq)) {
        mm_obj_dbg (self, "+ECSQ has no usable serving-RAT line");
        g_task_return_pointer (task, GUINT_TO_POINTER (0), NULL);
        g_object_unref (task);
        return;
    }

    mm_obj_dbg (self, "+ECSQ RSRP %d dBm / RSRQ %d dB -> quality %u%%",
                rsrp, rsrq, (guint) MM_RSRP_TO_QUALITY (rsrp));
    g_task_return_pointer (task, GUINT_TO_POINTER (MM_RSRP_TO_QUALITY (rsrp)), NULL);
    g_object_unref (task);
}

static void
load_signal_quality (MMIfaceModem       *self,
                     GAsyncReadyCallback callback,
                     gpointer            user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);
    mm_base_modem_at_command (MM_BASE_MODEM (self), "+ECSQ", 5, FALSE,
                              (GAsyncReadyCallback) ecsq_ready, task);
}

/*****************************************************************************/
/* Early power-up.                                                            */
/*                                                                            */
/* MMIfaceModem initialization checks AT+CPIN? before anything powers the     */
/* radio on, so an MD that comes up at CFUN=0 answers +CME ERROR: 14 (SIM      */
/* busy) and initialization fails.  The MediaTek MD is always in that state    */
/* after the Linux CCCI owner brings it up, so this hook (which runs before     */
/* mm_iface_modem_initialize) issues CFUN=1 when needed.  Best effort: any      */
/* error is logged and the parent implementation still runs.                   */

typedef struct {
    GAsyncReadyCallback callback;
    gpointer            user_data;
    guint               cfun;
    guint               efun_slots;
    guint               efun_mask;
} MtkSocInitializationStartedContext;

/* The MTK MD answers ATD with a proprietary '+EDMFAPP: ...' line *before* the
 * final OK. Without a registered handler ModemManager treats that line as an
 * unexpected reply, aborts the call start and the real call keeps running
 * inside the modem (a later hangup then fails with "This call was not
 * active"). Registering it as a URC leaves the ATD response as a plain OK.
 *
 * +EDMFAPP is not the only such line: the MD emits a whole family of
 * proprietary reports, and the IMS ones appear as soon as the modem starts
 * reporting IMS state. Some of them (+CIREGU, the IMS registration status
 * report, and +EDMFAPP itself) are periodic, so a single unexpected arrival
 * in the middle of any command/response pair aborts that operation. None of
 * them is modelled by ModemManager, so every observed or expected member is
 * registered here as an ignored unsolicited message.
 *
 * Registering these does NOT enable IMS; see
 * docs-local/mtk-soc/ims-investigation-20260929.md for why IMS cannot be
 * enabled for the SIM in the second physical slot on this firmware. */
static const gchar *mtk_soc_ignored_urcs[] = {
    "\\+EDMFAPP:\\s*(.*)",
    "\\+CIREGU:\\s*(.*)",
    "\\+CIREP:\\s*(.*)",
    "\\+EIREG:\\s*(.*)",
    "\\+EIMSCFG:\\s*(.*)",
    "\\+EIMSUI:\\s*(.*)",
    "\\+EIMSXUI:\\s*(.*)",
    "\\+EIMSREGURI:\\s*(.*)",
    "\\+EIMSREGRESP:\\s*(.*)",
    "\\+EIMSPDIS:\\s*(.*)",
    "\\+ESIPREGINFO:\\s*(.*)",
    "\\+ENAPTR:\\s*(.*)",
};

static void
ignored_urc_received (MMBroadbandModemMtkSoc *self,
                      GMatchInfo              *match_info)
{
    g_autofree gchar *line = NULL;

    line = g_match_info_fetch (match_info, 0);
    mm_obj_dbg (self, "ignoring MediaTek unsolicited response: %s", line);
}

/* The MD reports SIM insert/remove on its own:
 *
 *   +ESIMS: <status>,<something>        e.g.  "+ESIMS: 0,11" when the tray
 *                                       (both cards at once on this board) is
 *                                       pulled
 *
 * Nothing handled it, so ModemManager kept advertising the old SIM forever:
 * pulling the tray left the SIM objects, the registration and the data call
 * exactly as they were.  The line was not even in the ignored-URC list, so it
 * also arrived in the middle of unrelated command/response pairs.
 *
 * Registering it and triggering the standard SIM re-probe fixes both.  This is
 * the same shape the cinterion plugin uses for its ^SCKS report. */
#define MTK_SOC_LAST_ESIMS "mtk-soc-last-esims-status"

static void
esims_urc_received (MMBroadbandModemMtkSoc *self,
                    GMatchInfo              *match_info)
{
    g_autofree gchar *line = NULL;
    g_autofree gchar *status = NULL;
    const gchar      *last;

    line = g_match_info_fetch (match_info, 0);

    /* "+ESIMS: <status>,<other>" - the first field is what changes on a
     * hot-plug (1 with the cards in, 0 once the tray is pulled). */
    if (match_info && g_match_info_get_match_count (match_info) > 1)
        status = g_match_info_fetch (match_info, 1);
    if (status)
        status = g_strstrip (status);

    last = g_object_get_data (G_OBJECT (self), MTK_SOC_LAST_ESIMS);
    if (status && last && g_strcmp0 (status, last) == 0) {
        mm_obj_dbg (self, "SIM status unchanged (%s), not reprobing", status);
        return;
    }

    mm_obj_info (self, "SIM status report: %s", line);
    g_object_set_data_full (G_OBJECT (self), MTK_SOC_LAST_ESIMS,
                            g_strdup (status ? status : ""), g_free);

    /* A full disable + reprobe is the standard MM way to pick up a SIM change
     * (the cinterion plugin does the same from its ^SCKS report).  Doing it on
     * every report instead would leave the modem re-initializing whenever the
     * modem repeats the status, which is what made the UI sit on "loading"
     * and re-request the location permission over and over. */
    mm_iface_modem_process_sim_event (MM_IFACE_MODEM (self));
}

static void
setup_sim_status_handler (MMBroadbandModemMtkSoc *self)
{
    MMPortSerialAt *port;
    g_autoptr(GRegex) regex = NULL;

    port = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    if (!port) {
        mm_obj_warn (self, "no primary AT port; SIM status handler not set");
        return;
    }

    regex = g_regex_new ("\\+ESIMS:\\s*([0-9]+)", G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, NULL);
    mm_port_serial_at_add_unsolicited_msg_handler (port,
                                                   regex,
                                                   (MMPortSerialAtUnsolicitedMsgFn) esims_urc_received,
                                                   self,
                                                   NULL);
    mm_obj_dbg (self, "registered MediaTek SIM status handler");
}

static void
setup_ignored_unsolicited_handlers (MMBroadbandModemMtkSoc *self)
{
    MMPortSerialAt *port;
    guint           i;

    port = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    if (!port) {
        mm_obj_warn (self, "no primary AT port found; MediaTek URC handlers not set");
        return;
    }

    for (i = 0; i < G_N_ELEMENTS (mtk_soc_ignored_urcs); i++) {
        g_autoptr(GRegex) regex = NULL;

        regex = g_regex_new (mtk_soc_ignored_urcs[i], G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, NULL);
        mm_port_serial_at_add_unsolicited_msg_handler (port,
                                                       regex,
                                                       (MMPortSerialAtUnsolicitedMsgFn) ignored_urc_received,
                                                       self,
                                                       NULL);
    }

    mm_obj_dbg (self, "registered %u MediaTek unsolicited handlers in %s",
                (guint) G_N_ELEMENTS (mtk_soc_ignored_urcs),
                mm_port_get_device (MM_PORT (port)));

    /* +ESIMS is handled, not ignored: it is the SIM hot-plug report. */
    setup_sim_status_handler (self);
}

static void
continue_initialization_with_parent (MMBroadbandModem *self,
                                     MtkSocInitializationStartedContext *ctx)
{
    GAsyncReadyCallback callback = ctx->callback;
    gpointer user_data = ctx->user_data;

    g_free (ctx);

    if (MM_BROADBAND_MODEM_CLASS (mm_broadband_modem_mtk_soc_parent_class)->initialization_started) {
        MM_BROADBAND_MODEM_CLASS (mm_broadband_modem_mtk_soc_parent_class)->initialization_started (
            self, callback, user_data);
        return;
    }

    /* Should not happen with the supported ModemManager releases. */
    {
        GTask *task = g_task_new (self, NULL, callback, user_data);
        g_task_return_pointer (task, NULL, NULL);
        g_object_unref (task);
    }
}

/* The MD boots with +CGSMS=1 (circuit switched). There is no CS domain on an
 * LTE/NR-only network, so every MO SMS is rejected with +CME ERROR: 331 (no
 * network service) before it ever reaches the network. Selecting "packet
 * domain preferred" (TS 27.007 10.1.9: 3 = PS preferred, CS fallback) makes
 * SMS-over-NAS/SGs be attempted first and keeps CS as the fallback wherever it
 * still exists.  NOTE: the value used to be 2, which the spec defines as CS
 * preferred -- the opposite of the intent.  Measured on 2026-09-30: neither 1,
 * 2 nor 3 clears the +CME ERROR: 331 the MD returns for AT+CMGS here, so this
 * is a correctness fix, not the SMS unlock. This does not by itself make SMS work
 * here (there is no SMSoIP without IMS), but it removes a setting that can
 * only ever fail on this device.
 *
 * The MD answers ERROR if the command is sent while the radio is still coming
 * up, which is exactly the state right after the CFUN=1 above, so the command
 * is issued after initialization has been handed to the parent and retried a
 * few times instead of blocking the parent on it. */
typedef struct {
    MMBroadbandModemMtkSoc *self;   /* strong reference */
    guint                   attempts_left;
} MtkSocCgsmsContext;

#define MTK_SOC_CGSMS_ATTEMPTS 4
#define MTK_SOC_CGSMS_DELAY_S  5

static void
cgsms_retry (MtkSocCgsmsContext *cgsms);

static void
cgsms_finished (MtkSocCgsmsContext *cgsms)
{
    g_object_unref (cgsms->self);
    g_free (cgsms);
}

static void
cgsms_ready (MMBaseModem *self,
             GAsyncResult *res,
             MtkSocCgsmsContext *cgsms)
{
    g_autoptr(GError) error = NULL;

    if (mm_base_modem_at_command_finish (self, res, &error)) {
        mm_obj_dbg (cgsms->self, "SMS bearer set to packet-domain preferred (+CGSMS=3)");
        cgsms_finished (cgsms);
        return;
    }

    cgsms->attempts_left--;
    if (cgsms->attempts_left == 0) {
        mm_obj_dbg (cgsms->self,
                    "couldn't select the preferred SMS bearer after %u attempts: %s",
                    (guint) MTK_SOC_CGSMS_ATTEMPTS, error->message);
        cgsms_finished (cgsms);
        return;
    }

    mm_obj_dbg (cgsms->self, "preferred SMS bearer not selectable yet (%u attempts left): %s",
                cgsms->attempts_left, error->message);
    cgsms_retry (cgsms);
}

static gboolean
cgsms_retry_idle (MtkSocCgsmsContext *cgsms)
{
    mm_base_modem_at_command (MM_BASE_MODEM (cgsms->self), "+CGSMS=3", 3, FALSE,
                              (GAsyncReadyCallback) cgsms_ready, cgsms);
    return G_SOURCE_REMOVE;
}

static void
cgsms_retry (MtkSocCgsmsContext *cgsms)
{
    g_timeout_add_seconds (MTK_SOC_CGSMS_DELAY_S, (GSourceFunc) cgsms_retry_idle, cgsms);
}

static void
select_preferred_sms_bearer (MMBroadbandModemMtkSoc *self)
{
    MtkSocCgsmsContext *cgsms;

    cgsms = g_new0 (MtkSocCgsmsContext, 1);
    cgsms->self = g_object_ref (self);
    cgsms->attempts_left = MTK_SOC_CGSMS_ATTEMPTS;
    cgsms_retry (cgsms);
}

static void
set_cgsms_and_continue (MMBroadbandModemMtkSoc *self,
                        MtkSocInitializationStartedContext *ctx)
{
    select_preferred_sms_bearer (self);
    continue_initialization_with_parent (MM_BROADBAND_MODEM (self), ctx);
}

/* Bring up every reported SIM slot (dual SIM dual standby).
 *
 * The MD comes up with AT+EFUN=0/1, i.e. exactly one slot powered, so the second
 * physical slot answers AT+ESLOTSINFO? with "+CME ERROR: 14" (SIM busy) for the
 * whole session. Stock Android sends AT+EFUN=<mask> from
 * RmcRadioRequestHandler::bootupSetRadioPower on every boot (mask =
 * ~(-1 << getSimCount()), overridable via persist.vendor.radio.sim.mode), which
 * is what the mainline owner is missing.
 *
 * run23 kept this read-only because raising the mask correlated with losing
 * network registration. run25 (2026-09-29) showed that correlation was wrong:
 * the variable that decides registration is the modem's *major* SIM
 * (AT+ESIMMAP = 1 << slot, extracted from stock
 * RmcCapabilitySwitchRequestHandler::requestSetRadioCapability), and that value
 * persists in SBP NVRAM across reboots. With the major SIM on slot 1
 * (AT+ESIMMAP=1) the modem registers and attaches on LTE while the mask is 3 and
 * both slots report "+CPIN: READY"; every failure was measured with the major
 * SIM on slot 2. The mask is therefore raised here when it does not already
 * cover the reported slots.
 *
 * AT+EFUN is a runtime setting: it does not survive a reboot, so this runs on
 * every initialization. */
static void
set_slot_power_then_continue (MMBroadbandModemMtkSoc *self,
                              MtkSocInitializationStartedContext *ctx);

static void
efun_set_ready (MMBaseModem *self,
                GAsyncResult *res,
                MtkSocInitializationStartedContext *ctx);

static void
efun_query_ready (MMBaseModem *self,
                  GAsyncResult *res,
                  MtkSocInitializationStartedContext *ctx)
{
    g_autoptr(GError) error = NULL;
    const gchar *response;
    const gchar *value;
    gchar *endptr = NULL;
    guint64 parsed;
    guint current = 0;
    gboolean known = FALSE;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response)
        mm_obj_dbg (MM_BROADBAND_MODEM_MTK_SOC (self), "couldn't query AT+EFUN: %s",
                    error->message);
    else {
        value = mm_strip_tag (response, "+EFUN:");
        if (value) {
            parsed = g_ascii_strtoull (value, &endptr, 10);
            if (endptr != value && parsed <= 0xff) {
                current = (guint) parsed;
                known = TRUE;
            }
        }
    }

    if (known && current != ctx->efun_mask) {
        g_autofree gchar *cmd = g_strdup_printf ("AT+EFUN=%u", (guint) ctx->efun_mask);

        mm_obj_info (MM_BROADBAND_MODEM_MTK_SOC (self),
                     "powering every SIM slot: AT+EFUN=%u (was 0x%x of %u reported slot(s))",
                     (guint) ctx->efun_mask, current, (guint) ctx->efun_slots);
        mm_base_modem_at_command (MM_BASE_MODEM (self), cmd, 5, FALSE,
                                  (GAsyncReadyCallback) efun_set_ready, ctx);
        return;
    }

    mm_obj_dbg (MM_BROADBAND_MODEM_MTK_SOC (self),
                "SIM slot power mask 0x%x covers all %u reported slot(s)",
                current, (guint) ctx->efun_slots);

    set_cgsms_and_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
}

static void
efun_set_ready (MMBaseModem *self,
                GAsyncResult *res,
                MtkSocInitializationStartedContext *ctx)
{
    g_autoptr(GError) error = NULL;

    if (!mm_base_modem_at_command_finish (self, res, &error))
        mm_obj_warn (self, "couldn't raise the SIM slot power mask: %s", error->message);

    set_cgsms_and_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
}

static void
eslotsinfo_ready (MMBaseModem *self,
                  GAsyncResult *res,
                  MtkSocInitializationStartedContext *ctx)
{
    g_autoptr(GError) error = NULL;
    const gchar *response;
    const gchar *value;
    gchar *endptr = NULL;
    guint64 parsed;
    guint n_slots = 2; /* the PGZ110 tray always has two slots */

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response)
        mm_obj_dbg (MM_BROADBAND_MODEM_MTK_SOC (self), "couldn't query the SIM slots: %s",
                    error->message);
    else {
        value = mm_strip_tag (response, "+ESLOTSINFO:");
        if (value) {
            parsed = g_ascii_strtoull (value, &endptr, 10);
            if (endptr != value && parsed > 0 && parsed <= 4)
                n_slots = (guint) parsed;
        }
    }

    ctx->efun_slots = n_slots;
    ctx->efun_mask = (1u << n_slots) - 1u;
    mm_base_modem_at_command (MM_BASE_MODEM (self), "+EFUN?", 5, FALSE,
                              (GAsyncReadyCallback) efun_query_ready, ctx);
}

static void
set_slot_power_then_continue (MMBroadbandModemMtkSoc *self,
                              MtkSocInitializationStartedContext *ctx)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self), "+ESLOTSINFO?", 5, FALSE,
                              (GAsyncReadyCallback) eslotsinfo_ready, ctx);
}

static void
cfun_set_ready (MMBaseModem *self,
                GAsyncResult *res,
                MtkSocInitializationStartedContext *ctx)
{
    g_autoptr(GError) error = NULL;

    if (!mm_base_modem_at_command_finish (self, res, &error))
        mm_obj_warn (self, "couldn't power up the modem with CFUN=1: %s", error->message);
    set_slot_power_then_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
}

static void
cfun_query_ready (MMBaseModem *self,
                  GAsyncResult *res,
                  MtkSocInitializationStartedContext *ctx)
{
    g_autoptr(GError) error = NULL;
    const gchar *response;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        mm_obj_warn (self, "couldn't query CFUN: %s", error->message);
        set_slot_power_then_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
        return;
    }

    response = mm_strip_tag (response, "+CFUN:");
    if (!mm_get_uint_from_str (response, &ctx->cfun)) {
        mm_obj_warn (self, "unexpected CFUN response: %s", response);
        set_slot_power_then_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
        return;
    }

    if (ctx->cfun == 1) {
        set_slot_power_then_continue (MM_BROADBAND_MODEM_MTK_SOC (self), ctx);
        return;
    }

    mm_obj_info (self, "MD radio is off (CFUN=%u); sending CFUN=1 before initialization",
                 ctx->cfun);
    mm_base_modem_at_command (self, "+CFUN=1", 5, FALSE,
                              (GAsyncReadyCallback) cfun_set_ready, ctx);
}

static void
initialization_started (MMBroadbandModem *self,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    MtkSocInitializationStartedContext *ctx;

    setup_ignored_unsolicited_handlers (MM_BROADBAND_MODEM_MTK_SOC (self));

    ctx = g_new0 (MtkSocInitializationStartedContext, 1);
    ctx->callback = callback;
    ctx->user_data = user_data;
    mm_base_modem_at_command (MM_BASE_MODEM (self), "+CFUN?", 3, FALSE,
                              (GAsyncReadyCallback) cfun_query_ready, ctx);
}

static gpointer
initialization_started_finish (MMBroadbandModem *self,
                               GAsyncResult *res,
                               GError **error)
{
    return MM_BROADBAND_MODEM_CLASS (mm_broadband_modem_mtk_soc_parent_class)->initialization_started_finish (
        self, res, error);
}

MMBroadbandModemMtkSoc *
mm_broadband_modem_mtk_soc_new (const gchar  *device,
                                const gchar  *physdev,
                                const gchar **drivers,
                                const gchar  *plugin,
                                guint16       vendor_id,
                                guint16       product_id)
{
    return g_object_new (MM_TYPE_BROADBAND_MODEM_MTK_SOC,
                         MM_BASE_MODEM_DEVICE, device,
                         MM_BASE_MODEM_PHYSDEV, physdev,
                         MM_BASE_MODEM_DRIVERS, drivers,
                         MM_BASE_MODEM_PLUGIN, plugin,
                         MM_BASE_MODEM_VENDOR_ID, vendor_id,
                         MM_BASE_MODEM_PRODUCT_ID, product_id,
                         MM_BASE_MODEM_DATA_NET_SUPPORTED, TRUE,
                         NULL);
}

static void
mm_broadband_modem_mtk_soc_init (MMBroadbandModemMtkSoc *self)
{
}

static void
mm_broadband_modem_mtk_soc_class_init (MMBroadbandModemMtkSocClass *klass)
{
    MMBroadbandModemClass *broadband_class = MM_BROADBAND_MODEM_CLASS (klass);

    broadband_class->initialization_started = initialization_started;
    broadband_class->initialization_started_finish = initialization_started_finish;
}
