/* ─────────────────────────────────────────
   core1_ids.c

   Bare-metal IDS running on Core 0.
   Called from main() poll loop.

   ids_init()  — call once after ENET ready
   ids_poll()  — call every main loop iter

   Uses STM0 for 100ms window timing.
   ───────────────────────────────────────── */

#include "MPC5748G.h"
#include "core1_ids.h"
#include "enet_dma.h"
#include "shared_mem.h"
#include "stm_timer.h"
#include "uart_log.h"
#include <string.h>
#include <stdint.h>

/* ─────────────────────────────────────────
   Phase name strings
   ───────────────────────────────────────── */
static const char* const phase_names[] = {
    "NONE",
    "TAU_IA",
    "TAU_EX",
    "TAU_LM",
    "TAU_IMP",
    "FULL_CHAIN"
};

/* ─────────────────────────────────────────
   IDS state
   ───────────────────────────────────────── */
static ids_window_t  g_window;
static uint32_t      g_window_count  = 0u;
static uint32_t      g_window_start  = 0u;  /* STM counts */
static uint8_t       g_ids_running   = 0u;

/* ─────────────────────────────────────────
   Integer log2 approximation
   Output: Q16.16 fixed point
   ───────────────────────────────────────── */
static uint32_t log2_fp(uint32_t x)
{
    if(x == 0u) return 0u;

    uint32_t msb = 0u;
    uint32_t tmp = x;
    while(tmp > 1u)
    {
        tmp >>= 1u;
        msb++;
    }

    uint32_t frac    = x - (1u << msb);
    uint32_t frac_fp = 0u;

    if(msb > 0u)
    {
        frac_fp = (frac << 16) / (1u << msb);
    }

    return (msb << 16) | (frac_fp & 0xFFFFu);
}

/* ─────────────────────────────────────────
   Shannon entropy, Q5.3 fixed point
   Value 245 ≈ 7.66 bits (near-random)
   ───────────────────────────────────────── */
static uint32_t calc_entropy(
    uint32_t *hist,
    uint32_t  total)
{
    if(total == 0u) return 0u;

    uint32_t entropy_acc = 0u;
    uint32_t log2_total  = log2_fp(total);

    for(uint16_t i = 0u; i < 256u; i++)
    {
        if(hist[i] == 0u) continue;

        uint32_t count  = hist[i];
        uint32_t log2_c = log2_fp(count);

        uint32_t log2_inv_p = log2_total -
                              log2_c;

        entropy_acc += (count *
                       (log2_inv_p >> 8u)) /
                       total;
    }

    return entropy_acc >> 3u;
}

/* ─────────────────────────────────────────
   Parse one Ethernet frame into window stats
   Handles: untagged, 802.1Q VLAN, QinQ,
            IPv4, ICMP, UDP, fragments
   ───────────────────────────────────────── */
static void parse_frame(
    uint8_t      *frame,
    uint16_t      frame_len,
    ids_window_t *win)
{
    if(frame == NULL || frame_len < 14u)
        return;

    win->total_packets++;
    win->total_bytes += frame_len;

    uint16_t eth_type =
        ((uint16_t)frame[12] << 8) |
        (uint16_t)frame[13];

    uint16_t ip_start = 14u;

    if(eth_type == 0x8100u)
    {
        eth_type =
            ((uint16_t)frame[16] << 8) |
            (uint16_t)frame[17];
        ip_start = 18u;
    }

    if(eth_type == 0x88A8u ||
       eth_type == 0x9100u)
    {
        eth_type =
            ((uint16_t)frame[ip_start + 4u] << 8) |
            (uint16_t)frame[ip_start + 5u];
        ip_start += 8u;
    }

    if(eth_type != 0x0800u) return;
    if(frame_len < ip_start + 20u) return;

    uint8_t  ip_ver  = (frame[ip_start] >> 4u);
    uint8_t  ip_ihl  = (frame[ip_start] &
                        0x0Fu) * 4u;

    if(ip_ver != 4u || ip_ihl < 20u) return;

    uint8_t  ip_proto = frame[ip_start + 9u];

    uint16_t ip_id =
        ((uint16_t)frame[ip_start + 4u] << 8) |
        (uint16_t)frame[ip_start + 5u];

    uint16_t ip_flags_frag =
        ((uint16_t)frame[ip_start + 6u] << 8) |
        (uint16_t)frame[ip_start + 7u];

    uint8_t  ip_mf   =
        (uint8_t)((ip_flags_frag >> 13u) & 0x01u);
    uint16_t ip_frag =
        ip_flags_frag & 0x1FFFu;

    uint8_t is_frag = (ip_mf || ip_frag > 0u) ?
                      1u : 0u;

    if(is_frag)
    {
        win->frag_count++;

        if(ip_id == IDS_FIXED_ID)
        {
            win->fixed_id_count++;
        }
    }

    uint16_t trans_start = ip_start + ip_ihl;

    if(frame_len < trans_start + 4u) return;

    if(ip_proto == 1u)
    {
        uint8_t icmp_type = frame[trans_start];
        uint8_t icmp_code = frame[trans_start + 1u];

        if(icmp_type == 8u && icmp_code == 0u)
        {
            win->icmp_echo_count++;

            if(frame_len > trans_start + 12u)
            {
                uint8_t *icmp_data =
                    frame + trans_start + 8u;

                if(icmp_data[0] == 'C' &&
                   icmp_data[1] == 'D' &&
                   icmp_data[2] == 'I')
                {
                    win->icmp_echo_count += 4u;
                }
            }
        }

        if(icmp_type == 11u)
        {
            win->icmp_te_count++;
        }
    }

    if(ip_proto == 17u)
    {
        if(frame_len < trans_start + 8u) return;

        uint16_t udp_dport =
            ((uint16_t)frame[trans_start + 2u]
             << 8) |
            (uint16_t)frame[trans_start + 3u];

        uint16_t udp_len =
            ((uint16_t)frame[trans_start + 4u]
             << 8) |
            (uint16_t)frame[trans_start + 5u];

        if(udp_dport == 5001u)
        {
            win->udp_5001_count++;
        }

        if(udp_len > IDS_ENTROPY_THRESH)
        {
            win->udp_large_count++;
        }

        uint16_t payload_start = trans_start + 8u;

        if(frame_len > payload_start)
        {
            uint16_t payload_len =
                frame_len - payload_start;

            for(uint16_t j = 0u;
                j < payload_len; j++)
            {
                uint8_t byte =
                    frame[payload_start + j];
                win->byte_histogram[byte]++;
                win->total_payload_bytes++;
            }
        }
    }
}

/* ─────────────────────────────────────────
   Detection rules — returns alert bitmask
   ───────────────────────────────────────── */
static uint8_t run_detection(
    ids_window_t *win)
{
    uint8_t flags = ALERT_NONE;

    if(win->icmp_echo_count >
       IDS_ICMP_RATE_THRESH)
    {
        flags |= ALERT_TAU_IA_ICMP;
    }

    if(win->frag_count >
       IDS_FRAG_RATE_THRESH)
    {
        flags |= ALERT_TAU_EX_FRAG;
    }

    if(win->fixed_id_count > 0u)
    {
        flags |= ALERT_TAU_EX_FIXID;
    }

    if(win->entropy_fp >
       IDS_ENTROPY_THRESH)
    {
        flags |= ALERT_TAU_EX_ENTROPY;
    }

    if(win->udp_5001_count >
       IDS_UDP5001_THRESH)
    {
        flags |= ALERT_TAU_EX_UDP5001;
    }

    static uint32_t silence_count = 0u;
    static uint8_t  traffic_seen  = 0u;

    if(win->total_packets > 0u)
    {
        traffic_seen  = 1u;
        silence_count = 0u;
    }
    else if(traffic_seen)
    {
        silence_count++;
        if(silence_count >= IDS_SILENCE_THRESH)
            flags |= ALERT_TAU_LM_SILENCE;
    }

    if((flags & ALERT_TAU_IA_ICMP) &&
       (flags & ALERT_TAU_EX_FRAG))
    {
        flags |= ALERT_FULL_CHAIN;
    }

    return flags;
}

/* ─────────────────────────────────────────
   CCDI calculation
   mirror_active set by sja1105_configure_mirror
   cleared by shellcode (τLM exploit)
   ───────────────────────────────────────── */
static float calc_ccdi(void)
{
    float cdi_mirror =
        (SHM_MIRROR == 1u) ? 1.0f : 0.0f;

    return (CCDI_W_MIRROR  * cdi_mirror) +
           (CCDI_W_ENCRYPT * 0.0f)       +
           (CCDI_W_AUTH    * 0.0f)       +
           (CCDI_W_SIGN    * 0.0f);
}

/* ─────────────────────────────────────────
   Phase from alert flags
   ───────────────────────────────────────── */
static uint8_t determine_phase(uint8_t flags)
{
    if(flags & ALERT_FULL_CHAIN)
        return PHASE_FULL_CHAIN;

    if(flags & ALERT_TAU_LM_SILENCE)
        return PHASE_TAU_LM;

    if(flags & (ALERT_TAU_EX_FRAG    |
                ALERT_TAU_EX_FIXID   |
                ALERT_TAU_EX_ENTROPY |
                ALERT_TAU_EX_UDP5001))
        return PHASE_TAU_EX;

    if(flags & ALERT_TAU_IA_ICMP)
        return PHASE_TAU_IA;

    return PHASE_NONE;
}

/* ─────────────────────────────────────────
   UART output — format parsed by
   Python ids_monitor.py
   ───────────────────────────────────────── */
static void output_ids_window(
    ids_window_t *win,
    uint8_t       phase)
{
    uint8_t has_alert = (win->alert_flags != ALERT_NONE);

    /* Normal windows: 1 line per second */
    if(!has_alert && (g_window_count % 10u) != 0u) return;

    uint32_t t_s  = win->window_start_ms / 1000u;
    uint32_t t_ds = (win->window_start_ms % 1000u) / 100u;

    uart_log("[IDS] #");
    uart_log_uint(g_window_count);
    uart_log(" t=");
    uart_log_uint(t_s);
    uart_log(".");
    uart_log_uint(t_ds);
    uart_log("s  pkts=");
    uart_log_uint(win->total_packets);

    if(win->icmp_echo_count > 0u)
    {
        uart_log("  ICMP=");
        uart_log_uint(win->icmp_echo_count);
    }
    if(win->frag_count > 0u)
    {
        uart_log("  FRAG=");
        uart_log_uint(win->frag_count);
    }
    if(win->fixed_id_count > 0u)
    {
        uart_log("  FIXID=");
        uart_log_uint(win->fixed_id_count);
    }

    uart_log("  H=");
    uart_log_uint(win->entropy_fp);
    uart_log("  CCDI=");
    uart_log_float(win->ccdi);
    uart_log("  ");
    uart_log(phase_names[phase]);
    uart_log("\r\n");

    if(!has_alert) return;

    uart_log("  >> ");
    if(win->alert_flags & ALERT_TAU_IA_ICMP)    uart_log("ICMP_RATE ");
    if(win->alert_flags & ALERT_TAU_EX_FRAG)    uart_log("FRAG_RATE ");
    if(win->alert_flags & ALERT_TAU_EX_FIXID)   uart_log("FIXED_ID ");
    if(win->alert_flags & ALERT_TAU_EX_ENTROPY) uart_log("HIGH_ENTROPY ");
    if(win->alert_flags & ALERT_TAU_EX_UDP5001) uart_log("UDP5001 ");
    if(win->alert_flags & ALERT_TAU_LM_SILENCE) uart_log("SILENCE ");
    if(win->alert_flags & ALERT_FULL_CHAIN)     uart_log("FULL_CHAIN ");
    uart_log("CCDI=");
    uart_log_float(win->ccdi);
    uart_log("\r\n");
}

/* ─────────────────────────────────────────
   Write IDS results to shared memory
   msync barriers ensure Core 1 sees update
   ───────────────────────────────────────── */
static void update_shared_memory(
    ids_window_t *win,
    uint8_t       phase,
    uint32_t      window_count)
{
    __asm__ volatile("msync" ::: "memory");

    SHM_IDS.magic         = IDS_SHARED_MAGIC;
    SHM_IDS.alert_flags   = (uint32_t)win->alert_flags;
    SHM_IDS.phase         = (uint32_t)phase;
    SHM_IDS.total_packets = win->total_packets;
    SHM_IDS.icmp_count    = win->icmp_echo_count;
    SHM_IDS.frag_count    = win->frag_count;
    SHM_IDS.entropy_fp    = win->entropy_fp;
    SHM_IDS.ccdi          = win->ccdi;
    SHM_IDS.timestamp_ms  = win->window_start_ms;
    SHM_IDS.window_count  = window_count;

    __asm__ volatile("msync" ::: "memory");
}

/* ─────────────────────────────────────────
   Close the current window:
   compute entropy, run detection,
   output UART, update shared memory,
   open new window.
   ───────────────────────────────────────── */
static void close_window(void)
{
    g_window.entropy_fp = calc_entropy(
        g_window.byte_histogram,
        g_window.total_payload_bytes);

    g_window.alert_flags = run_detection(&g_window);

    g_window.ccdi = calc_ccdi();

    uint8_t phase = determine_phase(
        g_window.alert_flags);

    output_ids_window(&g_window, phase);

    update_shared_memory(
        &g_window, phase, g_window_count);

    g_window_count++;

    /* Open new window                      */
    memset(&g_window, 0,
           sizeof(ids_window_t));

    g_window.window_start_ms =
        g_window_count * IDS_WINDOW_MS;

    g_window_start = stm0_get_count();
}

/* ─────────────────────────────────────────
   ids_init()
   Call once from main() after ENET is up.
   ───────────────────────────────────────── */
void ids_init(void)
{
    memset(&g_window, 0,
           sizeof(ids_window_t));
    g_window_count = 0u;
    g_window_start = stm0_get_count();
    g_ids_running  = 1u;

    uart_log("[IDS] Core 0 IDS ready"
             " window=100ms\r\n");
}

/* ─────────────────────────────────────────
   ids_poll()
   Call from main() tight loop.
   Reads one frame; closes window when
   100ms has elapsed.
   ───────────────────────────────────────── */
void ids_poll(void)
{
    if(!g_ids_running) return;

    /* Read one frame from DMA ring         */
    uint8_t  frame_buf[ENET_BUFFER_SIZE];
    uint16_t frame_len;

    frame_len = enet_dma_read_frame(
        frame_buf,
        (uint16_t)sizeof(frame_buf));

    if(frame_len > 0u)
    {
        parse_frame(frame_buf,
                    frame_len,
                    &g_window);
    }

    /* Close window every 100ms             */
    uint32_t elapsed =
        stm0_get_count() - g_window_start;

    if(elapsed >=
       (IDS_WINDOW_MS * STM_TICKS_PER_MS))
    {
        close_window();
    }
}
