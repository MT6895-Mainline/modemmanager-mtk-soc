/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef MM_MTK_MIPC_H
#define MM_MTK_MIPC_H

#include <glib.h>

G_BEGIN_DECLS

#define MM_MTK_MIPC_HEADER_SIZE 16
#define MM_MTK_MIPC_MAX_PAYLOAD G_MAXUINT16

/* Message ids used by the direct-IP bearer. */
#define MM_MTK_MIPC_TEST_REQ       0x0305
#define MM_MTK_MIPC_TEST_CNF       0x0306
#define MM_MTK_MIPC_OPEN_REQ       0x0301
#define MM_MTK_MIPC_OPEN_CNF       0x0302
#define MM_MTK_MIPC_DATA_RETRY_TIMER_REQ 0x021b
#define MM_MTK_MIPC_DATA_RETRY_TIMER_CNF 0x021c
#define MM_MTK_MIPC_DATA_ACT_REQ   0x0201
#define MM_MTK_MIPC_DATA_ACT_CNF   0x0202
#define MM_MTK_MIPC_DATA_DEACT_REQ 0x0203
#define MM_MTK_MIPC_DATA_DEACT_CNF 0x0204
#define MM_MTK_MIPC_DATA_GET_CALL_LIST_REQ 0x020f
#define MM_MTK_MIPC_DATA_GET_CALL_LIST_CNF 0x0210
/* qqcandy: MIPC clients must explicitly subscribe to the INDs they want.  Without
 * this the modem delivers no unsolicited message at all, so everything the
 * firmware reports on its own (IMS state/VoPS/registration, network registration,
 * SIM events) is invisible.  Payload is TLV 0x0100 = u16 message id. */
#define MM_MTK_MIPC_REGISTER_IND_REQ       0x0307
#define MM_MTK_MIPC_REGISTER_IND_CNF       0x0308
#define MM_MTK_MIPC_TLV_IND_MSG_ID         0x0100

#define MM_MTK_MIPC_CLOSE_REQ              0x0303
#define MM_MTK_MIPC_CLOSE_CNF              0x0304
#define MM_MTK_MIPC_REGISTER_CMD_REQ       0x030b
#define MM_MTK_MIPC_REGISTER_CMD_CNF       0x030c
#define MM_MTK_MIPC_SPI_CMD                0x8305
#define MM_MTK_MIPC_SPI_RSP                0x8306
#define MM_MTK_MIPC_SPI_ALLOC              0
#define MM_MTK_MIPC_SPI_FREE               1

/* The 0x201 request always carries this fixed-size URSP traffic descriptor. */
#define MM_MTK_MIPC_URSP_DESC_SIZE 672

/* Field limits from the vendor structs (array size including the NUL). */
#define MM_MTK_MIPC_MAX_APN_LEN        99
#define MM_MTK_MIPC_MAX_CREDENTIAL_LEN 63

/* TLV kinds used in the 0x202 confirmation. */
#define MM_MTK_MIPC_TLV_RESULT        0x0000
#define MM_MTK_MIPC_TLV_DATA_CALL_ID  0x0100
#define MM_MTK_MIPC_TLV_MTU           0x0123
#define MM_MTK_MIPC_TLV_INTERFACE_ID  0x0125
#define MM_MTK_MIPC_TLV_TRANS_INTF_ID 0x012a
#define MM_MTK_MIPC_TLV_IPV4_PREFIX   0x0128
#define MM_MTK_MIPC_TLV_IPV4_ADDRESS  0x8104
#define MM_MTK_MIPC_TLV_IPV4_GATEWAY  0x8121
#define MM_MTK_MIPC_TLV_DNS1          0x810e
#define MM_MTK_MIPC_TLV_DNS2          0x810f

/* Tag 0x0100 is reused per-message. In the 0x202 CNF it is the data call id;
 * in the 0x210 call-list CNF it is a byte array indexed by (cid - 1) whose
 * value is MIPC_CID_ACT_STATE (0 = deactivated, 1 = activated).
 * Measured on the device: the array is 50 entries; with a call accepted as
 * ID=1 the first byte reads 1, and the request needs ps = slot (ps = 0xff is
 * refused with result 21). */
#define MM_MTK_MIPC_TLV_CID_LIST      0x0100
#define MM_MTK_MIPC_CALL_LIST_ENTRIES 50

/* D2-layer result codes (vendor mipc_msg_tlv_const.h,
 * MIPC_RESULT_PDN_EXT_NETWORK_D2_CAUSE_*). D2CPM_IN_USE means a data call for
 * the requested profile is still up, so DATA_ACT cannot be accepted until it
 * is deactivated. */
#define MM_MTK_MIPC_RESULT_D2CPM_IN_USE 0x001416D7u

/* MIPC_DEACT_REASON_ENUM (vendor). */
#define MM_MTK_MIPC_DEACT_REASON_DONT_CARE               0
#define MM_MTK_MIPC_DEACT_REASON_NORMAL                  1
#define MM_MTK_MIPC_DEACT_REASON_FORCE_TO_LOCAL_RELEASE  6

typedef enum {
    MM_MTK_MIPC_ERROR_INVALID,
    MM_MTK_MIPC_ERROR_TRUNCATED,
    MM_MTK_MIPC_ERROR_DUPLICATE,
    MM_MTK_MIPC_ERROR_OVERSIZED,
} MMMtkMipcError;

#define MM_MTK_MIPC_ERROR (mm_mtk_mipc_error_quark ())
GQuark mm_mtk_mipc_error_quark (void);

typedef struct {
    guint16 message_id;
    guint8  ps;
    guint16 transaction_id;
    GBytes *payload;
} MMMtkMipcFrame;

/* Address bytes and SPI range are distinct from the outer frame transaction. */
typedef struct {
    guint32 transaction_id;
    guint32 action;
    guint32 min_spi;
    guint32 max_spi;
    guint32 spi;
    guint32 address_len;
    guint8  source[16];
    guint8  destination[16];
    guint8  protocol;
    guint8  mode;
} MMMtkMipcSpiRequest;

GBytes *mm_mtk_mipc_register_spi_request (guint16 transaction_id);
gboolean mm_mtk_mipc_parse_spi_request (const MMMtkMipcFrame *frame,
                                        MMMtkMipcSpiRequest *request,
                                        GError **error);
/* SPI=0 reports allocation failure; free uses 0/1 failure/success. */
GBytes *mm_mtk_mipc_spi_response (const MMMtkMipcFrame *command,
                                  const MMMtkMipcSpiRequest *request,
                                  guint32 spi_or_result);

/* Result of a DATA_ACT_CALL_CNF (0x202) parse. Only `result` is meaningful
 * when the modem reports a non-zero result code. */
typedef struct {
    guint32 result;
    guint8  call_id;
    guint32 interface_id;
    guint32 trans_intf_id;
    guint8  ipv4[4];
    guint8  gateway[4];
    guint32 ipv4_prefix;
    guint8  dns[2][4];
    guint32 mtu;
} MMMtkMipcDataActCnf;

void    mm_mtk_mipc_frame_clear (MMMtkMipcFrame *frame);
GBytes *mm_mtk_mipc_frame_build (guint16       message_id,
                                 guint8        ps,
                                 guint16       transaction_id,
                                 const guint8 *payload,
                                 gsize         payload_len);
GBytes *mm_mtk_mipc_test_request (guint8 ps, guint16 transaction_id);
GBytes *mm_mtk_mipc_register_ind_request (guint8       ps,
                                          guint16      transaction_id,
                                          guint16      ind_message_id,
                                          GError     **error);
GBytes *mm_mtk_mipc_open_request (guint8       ps,
                                  guint16      transaction_id,
                                  const gchar *client_name,
                                  GError     **error);

/* Builds the 784-byte-payload DATA_ACT_CALL_REQ (0x201) for one APN. The
 * username/password may be NULL/empty; they are always encoded as a NUL
 * terminated C string (minimum value length 1). */
GBytes *mm_mtk_mipc_data_act_request (guint8        ps,
                                      guint16       transaction_id,
                                      const gchar  *apn,
                                      const gchar  *user,
                                      const gchar  *password,
                                      GError      **error);

/* Same frame with an explicit APN_TYPE (TLV 0x0106): 1 = default/internet,
 * 2 = IMS.  The stock RIL asks for the IMS PDN with type 2 (see the
 * REUSE_ONLY frame below), so a plain "ims" APN sent as type 1 may create a
 * default-domain call instead of an IMS one. */
GBytes *mm_mtk_mipc_data_act_request_typed (guint8        ps,
                                            guint16       transaction_id,
                                            const gchar  *apn,
                                            const gchar  *user,
                                            const gchar  *password,
                                            guint32       apn_type,
                                            guint32       apn_index,
                                            GError      **error);

/* IMS PDN activation, byte-for-byte what the stock RIL sends right before the
 * modem reports IMS_PDN_IND state 2 and starts SIP registration.  It is NOT a
 * profile-creation frame: the modem already holds an enabled IMS profile
 * (AP profile type=0x2 apn=ims), and a full DATA_ACT frame is accepted
 * (result 0) without ever activating the PDN.  Payload, measured 2026-10-07:
 *   TLV 0x010F u32 = 1
 *   TLV 0x0102 u32 = 2      (APN_TYPE = IMS)
 *   TLV 0x010A u8  = 3
 *   TLV 0x010D      = 672-byte URSP descriptor carrying "ims"
 */
GBytes *mm_mtk_mipc_ims_retry_timer_request (guint8  ps,
                                             guint16 transaction_id);

GBytes *mm_mtk_mipc_ims_pdn_activate_request (guint8  ps,
                                              guint16 transaction_id);

/* Stock IMS early-exit frame: APN_TYPE=IMS, REUSE_ONLY, DNN="ims".
 * Does not carry a new APN profile or default-data credentials. */
GBytes *mm_mtk_mipc_data_ims_reuse_request (guint8 ps, guint16 transaction_id);

/* Builds the DATA_DEACT_CALL_REQ (0x203): tlv(0x0101, u8 call_id) plus
 * tlv(0x0102, u8 deact_reason). Both TLVs are 8-byte aligned by construction,
 * which the modem's parser requires. */
GBytes *mm_mtk_mipc_data_deact_request (guint8    ps,
                                        guint16   transaction_id,
                                        guint8    call_id,
                                        guint8    deact_reason,
                                        GError  **error);

/* Builds the DATA_GET_MD_DATA_CALL_LIST_REQ (0x20f): no payload. The modem
 * answers with which cids are still active (see MM_MTK_MIPC_TLV_CID_LIST). */
GBytes *mm_mtk_mipc_data_get_call_list_request (guint8  ps,
                                                guint16 transaction_id);

/* Parses the call-list CNF into `states`: states[i] is the activation state of
 * cid (i + 1), i.e. the table is indexed by (cid - 1). At most `states_len`
 * entries are copied; `n_states` (optional) receives the copied count. */
gboolean mm_mtk_mipc_parse_call_list_cnf (GBytes  *payload,
                                          guint8  *states,
                                          gsize    states_len,
                                          gsize   *n_states,
                                          GError **error);

/* Consumes one complete frame; FALSE means that more bytes are needed. */
gboolean mm_mtk_mipc_stream_pop (GByteArray    *buffer,
                                 MMMtkMipcFrame *frame);

/* Generic TLV finder. On success `value`/`value_len` point into `payload`,
 * which must stay alive while the caller uses them. Returns FALSE for
 * malformed, absent or duplicate TLVs. */
gboolean mm_mtk_mipc_find_tlv (GBytes        *payload,
                               guint16        kind,
                               const guint8 **value,
                               guint16       *value_len,
                               GError       **error);

/* Returns FALSE for malformed, absent or duplicate TLVs. */
gboolean mm_mtk_mipc_find_u32_tlv (GBytes   *payload,
                                   guint16   kind,
                                   guint32  *value,
                                   GError  **error);

/* Parses a DATA_ACT_CALL_CNF (0x202) payload. When the modem reports a
 * non-zero result the remaining fields are left zeroed and TRUE is returned,
 * so the caller can report the result code. */
gboolean mm_mtk_mipc_parse_data_act_cnf (GBytes            *payload,
                                         MMMtkMipcDataActCnf *cnf,
                                         GError           **error);

G_END_DECLS

#endif
