/*
 * MicroarrayTechnology MAFP fingerprint reader driver for libfprint
 * USB ID: 3274:8012
 *
 * Protocol reverse-engineered from MicroarrayFingerprintDevice.dll v9.47.11.214
 * using Ghidra 12.0.4. The device uses the FPC/GROW-family bulk transfer
 * protocol (same packet framing as the R30X hobbyist module series).
 *
 * Endpoints:
 *   EP 0x03  OUT bulk  — commands to device
 *   EP 0x83  IN  bulk  — responses from device
 *   EP 0x82  IN  intr  — finger-detect events (used for waiting)
 *
 * Copyright (C) 2024  <jason@localhost>
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "microarray"

#include "drivers_api.h"

/* --------------------------------------------------------------------------
 * Protocol constants
 * -------------------------------------------------------------------------- */

/* Packet framing */
#define MA_EP_OUT           0x03
#define MA_EP_IN            0x83
#define MA_EP_INTR          0x82
#define MA_HDR_LEN          6       /* EF 01 FF FF FF FF */
#define MA_OVERHEAD         9       /* header + type(1) + length(2) */
#define MA_PKT_CMD          0x01
#define MA_PKT_ACK          0x07
#define MA_TIMEOUT_CMD      5000    /* ms */
#define MA_TIMEOUT_INTR     0       /* 0 = wait forever for finger */

/* FPC command opcodes (first byte of command payload) */
#define MA_CMD_GET_IMAGE    0x01    /* capture image; resp[0]=0 on success  */
#define MA_CMD_GEN_CHAR     0x02    /* extract features into char-buf slot  */
#define MA_CMD_REG_MODEL    0x05    /* merge char-bufs into template        */
#define MA_CMD_STORE_CHAR   0x06    /* save template to FID slot            */
#define MA_CMD_EMPTY        0x0D    /* erase ALL stored templates           */
#define MA_CMD_READ_INDEX   0x1F    /* bitmap of enrolled FID slots         */
#define MA_CMD_SEARCH       0x66    /* verify char-buf against FID          */
#define MA_CMD_DUP_CHECK    0x6F    /* duplicate-finger check               */

/* Enrolment requires this many successful captures before RegModel */
#define MA_ENROLL_SAMPLES   6

/* Response buffer: max response is ReadIndex = 35 bytes payload + 9 hdr = 44 */
#define MA_RESP_BUF         64

/* Handshake packet (raw, pre-framed, from Sensor::mfm_handshake) */
static const guint8 MA_HANDSHAKE_PKT[] = {
    0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01,           /* type = command */
    0x00, 0x02,     /* length = 2 */
    0x23,           /* instruction = handshake */
    0xA2            /* checksum */
};
#define MA_HANDSHAKE_PKT_LEN  G_N_ELEMENTS (MA_HANDSHAKE_PKT)
#define MA_HANDSHAKE_RESP_LEN 12

/* --------------------------------------------------------------------------
 * Device structure
 * -------------------------------------------------------------------------- */

struct _FpiDeviceMicroarray
{
  FpDevice       parent;
  FpiSsm        *task_ssm;
  gint           enroll_stage;
  gint           fid;              /* enrolled fingerprint ID slot */
  guint8        *resp_buf;         /* allocated response buffer    */
  GCancellable  *interrupt_cancellable;
  gboolean       waiting_for_lift; /* TRUE after each successful capture */
};

G_DECLARE_FINAL_TYPE (FpiDeviceMicroarray, fpi_device_microarray,
                      FPI, DEVICE_MICROARRAY, FpDevice)
G_DEFINE_TYPE (FpiDeviceMicroarray, fpi_device_microarray, FP_TYPE_DEVICE)

/* --------------------------------------------------------------------------
 * Packet helpers
 * -------------------------------------------------------------------------- */

/*
 * Build a framed FPC command packet.
 * Returns a newly allocated guint8 buffer (caller must g_free).
 * Sets *out_len to the total packet length.
 *
 * Format:
 *   EF 01 FF FF FF FF [type=01] [len_hi] [len_lo] [cmd_bytes...] [csum_hi] [csum_lo]
 * where len = cmd_len + 2  (payload + 2-byte checksum)
 */
static guint8 *
ma_build_cmd (const guint8 *cmd, gsize cmd_len, gsize *out_len)
{
    gsize total = MA_OVERHEAD + cmd_len + 2; /* 2 checksum bytes */
    guint8 *pkt = g_malloc (total);

    /* sync + address */
    pkt[0] = 0xEF;
    pkt[1] = 0x01;
    pkt[2] = 0xFF;
    pkt[3] = 0xFF;
    pkt[4] = 0xFF;
    pkt[5] = 0xFF;

    /* packet type */
    pkt[6] = MA_PKT_CMD;

    /* length = cmd_len + 2 (big-endian) */
    guint16 len = (guint16)(cmd_len + 2);
    pkt[7] = (guint8)(len >> 8);
    pkt[8] = (guint8)(len & 0xFF);

    /* command payload */
    memcpy (pkt + 9, cmd, cmd_len);

    /* 16-bit checksum: sum of bytes [6 .. 9+cmd_len-1] */
    guint16 csum = 0;
    for (gsize i = 6; i < 9 + cmd_len; i++)
        csum += pkt[i];
    pkt[9 + cmd_len]     = (guint8)(csum >> 8);
    pkt[9 + cmd_len + 1] = (guint8)(csum & 0xFF);

    *out_len = total;
    return pkt;
}

/*
 * Parse an FPC response packet.
 * Returns TRUE if header/checksum valid; resp_data and resp_data_len
 * point into buf (not copied).
 */
static gboolean
ma_parse_resp (const guint8 *buf, gsize buf_len,
               const guint8 **data_out, gsize *data_len_out,
               GError **error)
{
    if (buf_len < (gsize)(MA_OVERHEAD + 2)) {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "Response too short");
        return FALSE;
    }
    if (buf[0] != 0xEF || buf[1] != 0x01) {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "Bad sync header");
        return FALSE;
    }
    if (buf[6] != MA_PKT_ACK) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "Expected ACK (0x07), got 0x%02x", buf[6]);
        return FALSE;
    }
    guint16 len  = ((guint16)buf[7] << 8) | buf[8];
    gsize expected = (gsize)MA_OVERHEAD + len;
    if (buf_len < expected) {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "Response truncated");
        return FALSE;
    }
    /* verify checksum: sum of bytes [6 .. expected-3] */
    guint16 csum = 0;
    for (gsize i = 6; i < expected - 2; i++)
        csum += buf[i];
    guint16 got = ((guint16)buf[expected-2] << 8) | buf[expected-1];
    if (csum != got) {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                     "Checksum mismatch: want 0x%04x got 0x%04x", csum, got);
        return FALSE;
    }
    *data_out     = buf + MA_OVERHEAD;
    *data_len_out = (gsize)(len - 2);   /* strip 2 checksum bytes */
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Init state machine
 * -------------------------------------------------------------------------- */

enum {
    INIT_SEND_HANDSHAKE,
    INIT_RECV_HANDSHAKE,
    INIT_NUM_STATES,
};

static void
init_recv_cb (FpiUsbTransfer *transfer, FpDevice *device,
              gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    /* Basic handshake response check: just verify header bytes */
    if (transfer->actual_length >= 2 &&
        transfer->buffer[0] == 0xEF && transfer->buffer[1] == 0x01) {
        fp_dbg ("Handshake OK");
        fpi_ssm_mark_completed (ssm);
    } else {
        fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                      "Handshake response invalid"));
    }
}

static void
init_send_cb (FpiUsbTransfer *transfer, FpDevice *device,
              gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    fpi_ssm_next_state (ssm);
}

static void
init_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    FpiUsbTransfer *transfer;

    switch (fpi_ssm_get_cur_state (ssm)) {
    case INIT_SEND_HANDSHAKE: {
        guint8 *buf = g_memdup2 (MA_HANDSHAKE_PKT, MA_HANDSHAKE_PKT_LEN);
        transfer = fpi_usb_transfer_new (device);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_OUT,
                                         buf, MA_HANDSHAKE_PKT_LEN, g_free);
        fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, NULL,
                                 init_send_cb, ssm);
        break;
    }
    case INIT_RECV_HANDSHAKE:
        transfer = fpi_usb_transfer_new (device);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk (transfer, MA_EP_IN, MA_HANDSHAKE_RESP_LEN);
        fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, NULL,
                                 init_recv_cb, ssm);
        break;
    default:
        g_assert_not_reached ();
    }
}

static void
init_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    fpi_device_open_complete (device, error);
}

static void
ma_dev_open (FpDevice *device)
{
    GError *error = NULL;

    if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device),
                                       0, 0, &error)) {
        fpi_device_open_complete (device, error);
        return;
    }

    FpiSsm *ssm = fpi_ssm_new (device, init_run_state, INIT_NUM_STATES);
    fpi_ssm_start (ssm, init_ssm_done);
}

static void
ma_dev_close (FpDevice *device)
{
    GError *error = NULL;
    g_usb_device_release_interface (fpi_device_get_usb_device (device),
                                    0, 0, &error);
    fpi_device_close_complete (device, error);
}

/* --------------------------------------------------------------------------
 * Generic command send/receive helpers
 * -------------------------------------------------------------------------- */

/*
 * Sends a framed command and reads back the response into self->resp_buf.
 * On completion, calls fpi_ssm_next_state (ssm).
 * The caller is responsible for checking self->resp_buf[0] afterward.
 */

static void
cmd_recv_cb (FpiUsbTransfer *transfer, FpDevice *device,
             gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    fpi_ssm_next_state (ssm);
}

static void
cmd_send_cb (FpiUsbTransfer *transfer, FpDevice *device,
             gpointer user_data, GError *error)
{
    FpiSsm *ssm = user_data;
    if (error) {
        fpi_ssm_mark_failed (ssm, error);
        return;
    }
    fpi_ssm_next_state (ssm);
}

/* Submit a bulk-OUT command */
static void
ma_submit_cmd (FpiSsm *ssm, FpDevice *device,
               const guint8 *cmd, gsize cmd_len)
{
    gsize pkt_len;
    guint8 *pkt = ma_build_cmd (cmd, cmd_len, &pkt_len);
    FpiUsbTransfer *transfer = fpi_usb_transfer_new (device);
    transfer->ssm = ssm;
    fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_OUT,
                                     pkt, pkt_len, g_free);
    fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, NULL,
                             cmd_send_cb, ssm);
}

/* Submit a bulk-IN read into self->resp_buf */
static void
ma_submit_recv (FpiSsm *ssm, FpDevice *device, gsize expect_len)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    FpiUsbTransfer *transfer = fpi_usb_transfer_new (device);
    transfer->ssm = ssm;
    /* Point transfer buffer at our persistent resp_buf */
    fpi_usb_transfer_fill_bulk_full (transfer, MA_EP_IN,
                                     self->resp_buf, expect_len, NULL);
    fpi_usb_transfer_submit (transfer, MA_TIMEOUT_CMD, NULL,
                             cmd_recv_cb, ssm);
}

/* --------------------------------------------------------------------------
 * Enroll state machine
 * --------------------------------------------------------------------------
 *
 *  Pre-enrollment:
 *    ENROLL_HANDSHAKE / RECV      — reset device session
 *    ENROLL_READ_INDEX_PRE / RECV — CMD 0x1F: read FID bitmap
 *    ENROLL_EMPTY / RECV          — CMD 0x0D: only if all 30 slots full
 *
 *  Loop MA_ENROLL_SAMPLES times:
 *    ENROLL_GET_IMAGE / RECV      — CMD 0x01: poll until finger present
 *    ENROLL_GEN_CHAR / RECV       — CMD 0x02: extract features into char buffer
 *
 *  Complete:
 *    ENROLL_REG_MODEL / RECV      — CMD 0x05: merge char buffers into template
 *    ENROLL_STORE_CHAR / RECV     — CMD 0x06: store to self->fid (set in pre-check)
 */
enum {
    ENROLL_HANDSHAKE,            /* session reset — must call before every enrollment */
    ENROLL_RECV_HANDSHAKE,
    ENROLL_READ_INDEX_PRE,       /* CMD 0x1F — find free FID slot before starting */
    ENROLL_RECV_READ_INDEX_PRE,
    ENROLL_EMPTY,                /* CMD 0x0D — only if no free slot found */
    ENROLL_RECV_EMPTY,
    ENROLL_GET_IMAGE,
    ENROLL_RECV_IMAGE,
    ENROLL_GEN_CHAR,
    ENROLL_RECV_GEN_CHAR,
    ENROLL_REG_MODEL,
    ENROLL_RECV_REG_MODEL,
    ENROLL_STORE_CHAR,
    ENROLL_RECV_STORE_CHAR,
    ENROLL_NUM_STATES,
};

static gboolean
poll_get_image_cb (gpointer user_data)
{
    fpi_ssm_jump_to_state (user_data, ENROLL_GET_IMAGE);
    return G_SOURCE_REMOVE;
}

static void
enroll_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    guint8 cmd[8];

    switch (fpi_ssm_get_cur_state (ssm)) {

    case ENROLL_HANDSHAKE: {
        guint8 *buf = g_memdup2 (MA_HANDSHAKE_PKT, MA_HANDSHAKE_PKT_LEN);
        FpiUsbTransfer *t = fpi_usb_transfer_new (device);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk_full (t, MA_EP_OUT,
                                         buf, MA_HANDSHAKE_PKT_LEN, g_free);
        fpi_usb_transfer_submit (t, MA_TIMEOUT_CMD, NULL, cmd_send_cb, ssm);
        break;
    }

    case ENROLL_RECV_HANDSHAKE: {
        FpiUsbTransfer *t = fpi_usb_transfer_new (device);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, MA_EP_IN, MA_HANDSHAKE_RESP_LEN);
        fpi_usb_transfer_submit (t, MA_TIMEOUT_CMD, NULL, cmd_recv_cb, ssm);
        break;
    }

    case ENROLL_READ_INDEX_PRE:
        cmd[0] = MA_CMD_READ_INDEX;
        cmd[1] = 0x00;
        ma_submit_cmd (ssm, device, cmd, 2);
        break;

    case ENROLL_RECV_READ_INDEX_PRE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 35 + 2);
        break;

    case ENROLL_EMPTY: {
        /* Check bitmap from pre-enrollment ReadIndex */
        const guint8 *resp = self->resp_buf + MA_OVERHEAD;
        if (resp[0] == 0x00) {
            for (int byte = 0; byte < 4 && self->fid < 0; byte++) {
                for (int bit = 0; bit < 8; bit++) {
                    if (!(resp[1 + byte] & (1 << bit))) {
                        self->fid = byte * 8 + bit;
                        break;
                    }
                }
            }
        }
        if (self->fid >= 0) {
            fp_dbg ("FID slot %d free, skipping Empty", self->fid);
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }
        /* No free slots — erase all templates, use slot 0 */
        fp_dbg ("no free FID slots, clearing all templates (CMD 0x0D)");
        self->fid = 0;
        cmd[0] = MA_CMD_EMPTY;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;
    }

    case ENROLL_RECV_EMPTY:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    case ENROLL_GET_IMAGE:
        cmd[0] = MA_CMD_GET_IMAGE;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;

    case ENROLL_RECV_IMAGE:
        /* Response: 3 bytes payload, resp[0]=0 means image captured */
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    case ENROLL_GEN_CHAR:
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            /* No image (finger absent or sensor not ready) */
            if (self->waiting_for_lift) {
                /* Finger was just lifted — ready for next press */
                self->waiting_for_lift = FALSE;
                fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
                fp_dbg ("Finger lifted, waiting for next press");
            }
            fp_dbg ("GetImage not ready (0x%02x), retrying",
                    self->resp_buf[MA_OVERHEAD]);
            g_timeout_add (100, poll_get_image_cb, ssm);
            return;
        }
        if (self->waiting_for_lift) {
            /* Finger still down from previous capture — keep waiting */
            fp_dbg ("Waiting for finger lift...");
            g_timeout_add (100, poll_get_image_cb, ssm);
            return;
        }
        /* New finger press with valid image — proceed */
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        cmd[0] = MA_CMD_GEN_CHAR;
        cmd[1] = (guint8)(self->enroll_stage + 1);
        ma_submit_cmd (ssm, device, cmd, 2);
        break;

    case ENROLL_RECV_GEN_CHAR: {
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        /* Note: actual check happens in the callback; we use a simple approach
         * of checking after state transitions */
        /* Advance stage in next state entry */
        break;
    }

    /* We need to handle the stage increment after recv; do it via a dummy state
     * by just checking here at the start of the NEXT state. But since we can't
     * do that cleanly without extra states, we check at GEN_CHAR entry above.
     *
     * For stage counting: we increment after a successful GEN_CHAR recv.
     * Since recv state just does the USB and moves to next state, we increment
     * in REG_MODEL entry until stages are done.
     *
     * Simpler: jump back to GET_IMAGE if stage < SAMPLES, else fall through.
     * We do the increment and check at ENROLL_REG_MODEL entry. */

    case ENROLL_REG_MODEL:
        /* Check GenChar result and count sample */
        fp_dbg ("GenChar resp[0]=0x%02x stage=%d",
                self->resp_buf[MA_OVERHEAD], self->enroll_stage);
        if (self->resp_buf[MA_OVERHEAD] == 0x00) {
            self->enroll_stage++;
            fp_dbg ("stage %d / %d OK", self->enroll_stage, MA_ENROLL_SAMPLES);
            fpi_device_enroll_progress (device, self->enroll_stage, NULL, NULL);
        } else {
            g_warning ("microarray: GenChar failed (0x%02x), retrying stage",
                       self->resp_buf[MA_OVERHEAD]);
            fpi_device_enroll_progress (device, self->enroll_stage, NULL,
                                        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            self->waiting_for_lift = TRUE;
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }
        if (self->enroll_stage < MA_ENROLL_SAMPLES) {
            self->waiting_for_lift = TRUE;
            fpi_ssm_jump_to_state (ssm, ENROLL_GET_IMAGE);
            return;
        }
        fp_dbg ("all samples collected, sending RegModel (CMD 0x05)");
        cmd[0] = MA_CMD_REG_MODEL;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;

    case ENROLL_RECV_REG_MODEL:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    case ENROLL_STORE_CHAR:
        /* Check RegModel result */
        fp_dbg ("RegModel resp[0]=0x%02x, storing to FID slot %d",
                self->resp_buf[MA_OVERHEAD], self->fid);
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            g_warning ("microarray: RegModel FAILED with 0x%02x",
                       self->resp_buf[MA_OVERHEAD]);
            fpi_ssm_mark_failed (ssm,
                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                          "RegModel failed: 0x%02x",
                                          self->resp_buf[MA_OVERHEAD]));
            return;
        }
        /* self->fid was set during pre-enrollment ReadIndex or after Empty */
        cmd[0] = MA_CMD_STORE_CHAR;
        cmd[1] = 0x01;
        cmd[2] = (guint8)(self->fid >> 8);
        cmd[3] = (guint8)(self->fid & 0xFF);
        ma_submit_cmd (ssm, device, cmd, 4);
        break;

    case ENROLL_RECV_STORE_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    default:
        g_assert_not_reached ();
    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);

    if (error) {
        fpi_device_enroll_complete (device, NULL, error);
        return;
    }
    if (self->resp_buf[MA_OVERHEAD] != 0x00) {
        fpi_device_enroll_complete (device, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                      "StoreChar failed: 0x%02x",
                                      self->resp_buf[MA_OVERHEAD]));
        return;
    }

    /* Build an FpPrint encoding the FID */
    FpPrint *print = NULL;
    fpi_device_get_enroll_data (device, &print);
    fpi_print_set_type (print, FPI_PRINT_RAW);
    fpi_print_set_device_stored (print, TRUE);

    GVariant *data = g_variant_new ("(i)", self->fid);
    g_object_set (print, "fpi-data", data, NULL);

    fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
    fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
ma_enroll (FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    self->enroll_stage = 0;
    self->fid = -1;
    self->waiting_for_lift = FALSE;
    FpiSsm *ssm = fpi_ssm_new (device, enroll_run_state, ENROLL_NUM_STATES);
    fpi_ssm_start (ssm, enroll_ssm_done);
}

/* --------------------------------------------------------------------------
 * Verify state machine
 * -------------------------------------------------------------------------- */

enum {
    VERIFY_GET_IMAGE,
    VERIFY_RECV_IMAGE,
    VERIFY_GEN_CHAR,
    VERIFY_RECV_GEN_CHAR,
    VERIFY_SEARCH,
    VERIFY_RECV_SEARCH,
    VERIFY_NUM_STATES,
};

static void
verify_run_state (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    guint8 cmd[8];

    switch (fpi_ssm_get_cur_state (ssm)) {

    case VERIFY_GET_IMAGE:
        cmd[0] = MA_CMD_GET_IMAGE;
        ma_submit_cmd (ssm, device, cmd, 1);
        break;

    case VERIFY_RECV_IMAGE:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    case VERIFY_GEN_CHAR:
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fp_dbg ("GetImage not ready, retrying");
            fpi_ssm_jump_to_state (ssm, VERIFY_GET_IMAGE);
            return;
        }
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        cmd[0] = MA_CMD_GEN_CHAR;
        cmd[1] = 0x01;   /* use char buffer slot 1 for verification */
        ma_submit_cmd (ssm, device, cmd, 2);
        break;

    case VERIFY_RECV_GEN_CHAR:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    case VERIFY_SEARCH: {
        if (self->resp_buf[MA_OVERHEAD] != 0x00) {
            fpi_ssm_mark_failed (ssm,
                fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            return;
        }
        /* Get FID from enrolled print */
        FpPrint *print = NULL;
        fpi_device_get_verify_data (device, &print);
        GVariant *data = NULL;
        g_object_get (print, "fpi-data", &data, NULL);
        gint fid = 0;
        g_variant_get (data, "(i)", &fid);
        self->fid = fid;

        /* CMD 0x66 fid_hi fid_lo — verify against specific FID */
        cmd[0] = MA_CMD_SEARCH;
        cmd[1] = (guint8)(self->fid >> 8);
        cmd[2] = (guint8)(self->fid & 0xFF);
        ma_submit_cmd (ssm, device, cmd, 3);
        break;
    }

    case VERIFY_RECV_SEARCH:
        ma_submit_recv (ssm, device, MA_OVERHEAD + 3 + 2);
        break;

    default:
        g_assert_not_reached ();
    }
}

static void
verify_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);

    fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

    if (error) {
        /* Could be a retry error */
        fpi_device_verify_complete (device, error);
        return;
    }

    FpPrint *print = NULL;
    fpi_device_get_verify_data (device, &print);

    guint8 status = self->resp_buf[MA_OVERHEAD];
    if (status == 0x00) {
        fpi_device_verify_report (device, FPI_MATCH_SUCCESS, print, NULL);
    } else {
        fp_dbg ("Search result: 0x%02x (no match)", status);
        fpi_device_verify_report (device, FPI_MATCH_FAIL, print, NULL);
    }
    fpi_device_verify_complete (device, NULL);
}

static void
ma_verify (FpDevice *device)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (device);
    self->fid = -1;
    FpiSsm *ssm = fpi_ssm_new (device, verify_run_state, VERIFY_NUM_STATES);
    fpi_ssm_start (ssm, verify_ssm_done);
}

/* --------------------------------------------------------------------------
 * GObject boilerplate
 * -------------------------------------------------------------------------- */

static const FpIdEntry id_table[] = {
    { .vid = 0x3274, .pid = 0x8012, .driver_data = 0 },
    { .vid = 0,      .pid = 0,      .driver_data = 0 },
};

static void
fpi_device_microarray_init (FpiDeviceMicroarray *self)
{
    self->enroll_stage = 0;
    self->fid = -1;
    self->waiting_for_lift = FALSE;
    self->resp_buf = g_malloc (MA_RESP_BUF + MA_OVERHEAD + 4);
}

static void
fpi_device_microarray_finalize (GObject *object)
{
    FpiDeviceMicroarray *self = FPI_DEVICE_MICROARRAY (object);
    g_clear_pointer (&self->resp_buf, g_free);
    G_OBJECT_CLASS (fpi_device_microarray_parent_class)->finalize (object);
}

static void
fpi_device_microarray_class_init (FpiDeviceMicroarrayClass *klass)
{
    GObjectClass   *obj_class = G_OBJECT_CLASS (klass);
    FpDeviceClass  *dev_class = FP_DEVICE_CLASS (klass);

    obj_class->finalize = fpi_device_microarray_finalize;

    dev_class->id               = "microarray";
    dev_class->full_name        = "MicroarrayTechnology MAFP";
    dev_class->type             = FP_DEVICE_TYPE_USB;
    dev_class->id_table         = id_table;
    dev_class->nr_enroll_stages = MA_ENROLL_SAMPLES;
    dev_class->scan_type        = FP_SCAN_TYPE_PRESS;

    dev_class->open   = ma_dev_open;
    dev_class->close  = ma_dev_close;
    dev_class->enroll = ma_enroll;
    dev_class->verify = ma_verify;

    fpi_device_class_auto_initialize_features (dev_class);
}
