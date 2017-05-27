/*
 * Copyright (C) 2012-2017 Canonical
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>

#define OPT_ESCAPE_STRIP	0x00000001
#define OPT_MISSING_NEWLINE	0x00000002
#define OPT_LITERAL_STRINGS	0x00000004
#define OPT_SOURCE_NAME		0x00000008
#define OPT_FORMAT_STRIP	0x00000010
#define OPT_CHECK_WORDS		0x00000020

#define UNLIKELY(c)		__builtin_expect((c), 0)
#define LIKELY(c)		__builtin_expect((c), 1)

#define FLOAT_TINY		(0.0000001)
#define FLOAT_CMP(a, b)		(__builtin_fabs(a - b) < FLOAT_TINY)

#define PARSER_OK		(0)
#define PARSER_COMMENT_FOUND	(1)
#define PARSER_EOF		(256)
#define PARSER_CONTINUE		(512)

#define TOKEN_CHUNK_SIZE	(32768)
#define TABLE_SIZE		(4*16384)
#define HASH_MASK		(TABLE_SIZE - 1)

#define MAX_WORD_NODES		(26)

#define SIZEOF_ARRAY(x)		(sizeof(x) / sizeof(x[0]))

#define _VER_(major, minor, patchlevel)			\
	((major * 10000) + (minor * 100) + patchlevel)

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#if defined(__GNUC_PATCHLEVEL__)
#define NEED_GNUC(major, minor, patchlevel) 			\
	_VER_(major, minor, patchlevel) <= _VER_(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#else
#define NEED_GNUC(major, minor, patchlevel) 			\
	_VER_(major, minor, patchlevel) <= _VER_(__GNUC__, __GNUC_MINOR__, 0)
#endif
#else
#define NEED_GNUC(major, minor, patchlevel) 	(0)
#endif

#if defined(__GNUC__) && NEED_GNUC(4,6,0)
#define HOT __attribute__ ((hot))
#else
#define HOT
#endif

#if defined(__GNUC__) && NEED_GNUC(4,6,0)
#define NORETURN __attribute__ ((noreturn))
#else
#define NORETURN
#endif

/*
 *  Subset of tokens that we need to intelligently parse the kernel C source
 */
typedef enum {
	TOKEN_UNKNOWN,		/* No idea what token it is */
	TOKEN_NUMBER,		/* Integer */
	TOKEN_LITERAL_STRING,	/* "string" */
	TOKEN_LITERAL_CHAR,	/* 'x' */
	TOKEN_IDENTIFIER,	/* identifier */
	TOKEN_PAREN_OPENED,	/* ( */
	TOKEN_PAREN_CLOSED,	/* ) */
	TOKEN_SQUARE_OPENED,	/* [ */
	TOKEN_SQUARE_CLOSED,	/* ] */
	TOKEN_CPP,		/* # C pre-propressor */
	TOKEN_WHITE_SPACE,	/* ' ', '\t', '\r', '\n' white space */
	TOKEN_LESS_THAN,	/* < */
	TOKEN_GREATER_THAN,	/* > */
	TOKEN_COMMA,		/* , */
	TOKEN_ARROW,		/* -> */
	TOKEN_TERMINAL,		/* ; */
} token_type_t;

/*
 *  A token
 */
typedef struct {
	char *ptr;		/* Current end of the token during the lexical analysis */
	char *token;		/* The gathered string for this token */
	char *token_end;	/* end of the token */
	size_t len;		/* Length of the token buffer */
	token_type_t type;	/* The type of token we think it is */
} token_t;

/*
 *  Parser context
 */
typedef struct {
	unsigned char *ptr;		/* current data position */
	unsigned char *data;		/* The start data being parsed */
	unsigned char *data_end;	/* end of the data */
	bool skip_white_space;		/* Magic skip white space flag */
} parser_t;

/*
 *  Hash table entry (linked list of tokens)
 */
typedef struct hash_entry {
	struct hash_entry *next;
	char *token;
} hash_entry_t;

typedef int (*get_token_action_t)(parser_t *restrict p, token_t *restrict t, int ch);

/*
 *  printk format string table items
 */
typedef struct {
	char *format;	/* printk format string */
	size_t len;	/* length of format string */
} format_t;

typedef struct word_node {
	struct word_node *nodes[MAX_WORD_NODES];
	bool eow;	/* end of word? true = yes */
} word_node_t;

static uint32_t finds;
static uint32_t files;
static uint32_t lines;
static uint32_t lineno;
static uint32_t bad_spellings;

static uint8_t opt_flags = OPT_SOURCE_NAME;
static void (*token_cat)(token_t *restrict token, token_t *restrict token_to_add);
static char quotes[] = "\"";
static char space[] = " ";
static word_node_t word_nodes;

/*
 *  Kernel printk format specifiers
 */
static format_t formats[] = {
	{ "%", 1 },
	{ "s", 1 },
	{ "llu", 3 },
	{ "lld", 3 },
	{ "llx", 3 },
	{ "llX", 3 },
	{ "lu", 2 },
	{ "ld", 2 },
	{ "lx", 2 },
	{ "lX", 2 },
	{ "u", 1 },
	{ "d", 1 },
	{ "x", 1 },
	{ "X", 1 },
	{ "pF", 2 },
	{ "pf", 2 },
	{ "ps", 2 },
	{ "pSR", 3 },
	{ "pS", 2 },
	{ "pB", 2 },
	{ "pK", 2 },
	{ "pr", 2 },
	{ "pap", 3 },
	{ "pa", 2 },
	{ "pad", 3 },
	{ "*pE", 3 },
	{ "*pEa", 4 },
	{ "*pEc", 4 },
	{ "*pEh", 4 },
	{ "*pEn", 4 },
	{ "*pEo", 4 },
	{ "*pEp", 4 },
	{ "*pEs", 4 },
	{ "*ph", 3 },
	{ "*phC", 4 },
	{ "*phD", 4 },
	{ "*phN", 4 },
	{ "pM", 2 },
	{ "pMR", 3 },
	{ "pMF", 3 },
	{ "pm", 2 },
	{ "pmR", 3 },
	{ "pi4", 3 },
	{ "pI4", 3 },
	{ "pi4h", 4 },
	{ "pI4h", 4 },
	{ "pi4n", 4 },
	{ "pI4n", 4 },
	{ "pi4b", 4 },
	{ "pI4b", 4 },
	{ "pi4l", 4 },
	{ "pI4l", 4 },
	{ "pi6", 3 },
	{ "pI6", 3 },
	{ "pI6c", 4 },
	{ "piS", 3 },
	{ "pIS", 3 },
	{ "piSc", 4 },
	{ "pISc", 4 },
	{ "piSpc", 5 },
	{ "pISpc", 5 },
	{ "piSf", 4 },
	{ "pISf", 4 },
	{ "piSs", 4 },
	{ "pISs", 4 },
	{ "piSh", 4 },
	{ "pISh", 4 },
	{ "piSn", 4 },
	{ "pISn", 4 },
	{ "piSb", 4 },
	{ "pISb", 4 },
	{ "piSl", 4 },
	{ "pISl", 4 },
	{ "pUb", 3 },
	{ "pUB", 3 },
	{ "pUl", 3 },
	{ "pUL", 3 },
	{ "pd", 2 },
	{ "pd2", 3 },
	{ "pd3", 3 },
	{ "pd4", 3 },
	{ "pD", 2 },
	{ "pD2", 3 },
	{ "pD3", 3 },
	{ "pD4", 3 },
	{ "pg", 2 },
	{ "pV", 2 },
	{ "pC", 2 },
	{ "pCn", 3 },
	{ "pCr", 3 },
	{ "*pb", 3 },
	{ "*pbl", 4 },
	{ "pGp", 3 },
	{ "pGg", 3 },
	{ "pGv", 3 },
	{ "pNF", 3 },
};

/*
 *  hash table of printk like functions to scan for
 */
static hash_entry_t *hash_printks[TABLE_SIZE];

/*
 *  hash table of bad spellings
 */
static hash_entry_t *hash_bad_spellings[TABLE_SIZE];

/*
 *  various printk like functions to populate the
 *  hash_printks hash table
 */
static char *printks[] = {
	"ACPI_BIOS_ERROR",
	"ACPI_BIOS_WARNING",
	"ACPI_DEBUG_PRINT",
	"ACPI_DEBUG_PRINT_RAW",
	"ACPI_ERROR",
	"ACPI_ERROR_METHOD",
	"ACPI_EXCEPTION",
	"ACPI_INFO",
	"acpi_os_printf",
	"ACPI_WARNING",
	"airo_print_err",
	"airo_print_info",
	"amd64_err",
	"amd64_info",
	"amd64_notice",
	"amd64_warn",
	"apic_debug",
	"ASD_DPRINTK",
	"asd_printk",
	"ata_dev_printk",
	"ata_link_printk",
	"ata_port_printk",
	"ATH5K_PRINTF",
	"ath6kl_err",
	"ath6kl_info",
	"ath6kl_warn",
	"binder_user_error",
	"blogic_err",
	"blogic_info",
	"blogic_notice",
	"blogic_warn",
	"BNX2X_ERR",
	"bootx_printf",
	"brcmf_err",
	"BT_DBG",
	"BTE_PRINTK",
	"BTE_PRINTKV",
	"BT_ERR",
	"BT_ERR_RATELIMITED",
	"BT_INFO",
	"BT_WARN",
	"BUF_PRINT",
	"ci_dbg",
	"ci_dbg_print",
	"cmm_dbg",
	"cobalt_err",
	"cobalt_info",
	"cobalt_warn",
	"conf_message",
	"conf_warning",
	"cont",
	"core_dbg",
	"cow_printf",
	"ctcm_pr_debug",
	"CTCM_PR_DEBUG",
	"cvmx_dprintf",
	"CX18_ALSA_ERR",
	"CX18_ALSA_WARN",
	"CX18_DEBUG_ALSA_INFO",
	"CX18_DEBUG_INFO",
	"CX18_DEBUG_IOCTL",
	"CX18_DEBUG_WARN",
	"CX18_ERR",
	"CX18_INFO",
	"CX18_WARN",
	"cx231xx_coredbg",
	"cx231xx_isocdbg",
	"cx231xx_videodbg",
	"CX25821_ERR",
	"CX25821_INFO",
	"cx_err",
	"cx_info",
	"d2printk",
	"DAC960_Critical",
	"DAC960_Error",
	"DAC960_Info",
	"DAC960_Notice",
	"DAC960_Progress",
	"DAC960_UserCritical",
	"dbg",
	"_DBG",
	"DBG",
	"DBG1",
	"DBG2",
	"DBG3",
	"DBG4",
	"DBG_88E",
	"DBGA",
	"DBGA2",
	"DBGBH",
	"DBG_BYPASS",
	"DBG_CFG",
	"dbg_cmt",
	"DBG_CNT",
	"DBGDCONT",
	"dbg_eba",
	"DB_GEN",
	"DBG_ERR",
	"DBGERR",
	"dbg_find",
	"dbg_fmt",
	"dbg_fragtree",
	"dbg_fragtree2",
	"dbg_fsbuild",
	"DBG_FTL",
	"dbg_gc",
	"dbg_gen",
	"dbg_hid",
	"dbg_info",
	"DBGINFO",
	"dbg_inocache",
	"dbg_io",
	"DBG_IRT",
	"DBGISR",
	"dbg_jnl",
	"dbg_log",
	"DBG_LOG",
	"DBG_LOTS",
	"DBG_LOW",
	"dbg_lp",
	"dbg_memalloc",
	"dbg_mnt",
	"DBG_MSG",
	"dbg_noderef",
	"DBG_PORT",
	"dbgp_printk",
	"DBGPR",
	"dbgprint",
	"DBG_printk",
	"DBG_PRV1",
	"dbg_rcvry",
	"dbg_readinode",
	"dbg_readinode2",
	"dbg_reg",
	"DBG_REG",
	"dbg_regs",
	"DBG_RES",
	"DBG_RUN",
	"DBG_RUN_SG",
	"DBGS",
	"dbg_scan",
	"dbg_summary",
	"dbg_tnc",
	"DBG_TRC",
	"dbg_verbose",
	"dbg_wl",
	"dbg_xattr",
	"DB_PCM",
	"DB_RMT",
	"DB_RX",
	"DB_SMT",
	"DB_SNMP",
	"DB_TX",
	"dbug",
	"DCCP_BUG",
	"DCCP_CRIT",
	"dccp_debug",
	"dccp_pr_debug",
	"dccp_pr_debug_cat",
	"DCCP_WARN",
	"ddprintk",
	"ddprintk_cont",
	"DEB",
	"DEB1",
	"DEB2",
	"DEB3",
	"DEB_CAP",
	"deb_chk",
	"DEB_D",
	"deb_data",
	"deb_decode",
	"deb_eeprom",
	"deb_err",
	"deb_fe",
	"deb_fw",
	"deb_fwdata",
	"deb_fw_load",
	"deb_getf",
	"deb_hab",
	"deb_i2c",
	"DEB_I2C",
	"deb_i2c_read",
	"deb_i2c_write",
	"deb_info",
	"DEB_INT",
	"deb_irq",
	"deb_mem",
	"DEBPRINT",
	"DEBPRINTK",
	"deb_rc",
	"deb_rdump",
	"deb_readreg",
	"deb_reg",
	"DEB_S",
	"deb_setf",
	"deb_sram",
	"deb_ts",
	"deb_tuner",
	"_debug",
	"debug",
	"DEBUG",
	"DEBUG2",
	"DEBUG3",
	"DEBUG_API",
	"DEBUG_AUTOCONF",
	"debug_badness",
	"_debug_bug_printk",
	"DEBUGFS_OPS",
	"DEBUG_IRQ",
	"debug_log",
	"DEBUG_LOG",
	"DEBUGOUTBUF",
	"DEBUGP",
	"debug_pci",
	"debug_polling",
	"debug_putstr",
	"DEBUGREAD",
	"DEBUGTRDMA",
	"DEBUGTXINT",
	"DEBUGWRITE",
	"deb_uxfer",
	"deb_v8",
	"DEB_VBI",
	"deb_xfer",
	"dev",
	"dev_alert",
	"dev_alert_once",
	"dev_alert_ratelimited",
	"dev_crit",
	"dev_crit_once",
	"dev_crit_ratelimited",
	"dev_dbg",
	"dev_dbg_once",
	"dev_emerg",
	"dev_emerg_once",
	"dev_emerg_ratelimited",
	"dev_err",
	"dev_err_once",
	"dev_err_ratelimited",
	"dev_info_once",
	"dev_info_ratelimited",
	"dev_level_once",
	"dev_level_ratelimited",
	"dev_notice",
	"dev_notice_once",
	"dev_notice_ratelimited",
	"dev_printk",
	"dev_printk_emit",
	"dev_vprintk_emit",
	"dev_warn",
	"dev_warn_once",
	"dev_warn_ratelimited",
	"df_trace",
	"die",
	"D_INFO",
	"DIPRINTK",
	"D_ISR",
	"diva_log_info",
	"D_LED",
	"dlprintk",
	"DMCRIT",
	"DMDEBUG",
	"DMDEBUG_LIMIT",
	"DMEMIT",
	"DMERR",
	"DMERR_LIMIT",
	"DMESG",
	"DMESGE",
	"DMINFO",
	"DMSG",
	"DMWARN",
	"doc_dbg",
	"doc_err",
	"doc_info",
	"doc_vdbg",
	"dout",
	"DP",
	"DPC",
	"DPD",
	"DPD1",
	"DPE",
	"DPE1",
	"D_POWER",
	"dprint",
	"DPRINT",
	"DPRINT_CONFIG",
	"dprintf",
	"Dprintf",
	"DPRINTF",
	"dprintf0",
	"dprintf1",
	"dprintf2",
	"dprintf3",
	"dprintf4",
	"dprintf5",
	"dprintk",
	"Dprintk",
	"DPRINTK",
	"dprintk0",
	"dprintk_cont",
	"dprintk_i2c",
	"dprintk_mmu",
	"dprintk_pte",
	"dprintk_rcu",
	"dprintk_sr",
	"dprintk_tscheck",
	"DPRINT_ovfl",
	"DPRINT_TLA",
	"D_QOS",
	"D_RADIO",
	"D_RATE",
	"D_RF_KILL",
	"DRM_DEBUG",
	"DRM_DEBUG_ATOMIC",
	"DRM_DEBUG_DRIVER",
	"DRM_DEBUG_KMS",
	"DRM_DEBUG_PRIME",
	"DRM_DEBUG_VBL",
	"DRM_ERROR",
	"DRM_ERROR_RATELIMITED",
	"DRM_INFO",
	"DRM_INFO_ONCE",
	"DRM_NOTE",
	"DRM_WARN",
	"dsb",
	"D_SCAN",
	"DSSDBG",
	"DSSERR",
	"DSSWARN",
	"D_STATS",
	"D_TEMP",
	"dtrc",
	"D_TX",
	"DTX",
	"D_TXPOWER",
	"D_TX_REPLY",
	"dump_printf",
	"DUMP_printk",
	"dump_stack_set_arch_desc",
	"DUMP_VALUE",
	"DWC2_TRACE_SCHEDULER",
	"DWC2_TRACE_SCHEDULER_VB",
	"D_WEP",
	"dxtrace",
	"dynamic_pr_debug",
	"early_panic",
	"early_print",
	"early_printk",
	"ec_dbg_evt",
	"ec_dbg_raw",
	"ec_dbg_req",
	"ec_dbg_stm",
	"ecryptfs_printk",
	"e_dbg",
	"e_dev_err",
	"e_dev_info",
	"e_dev_warn",
	"e_err",
	"efi_printk",
	"e_info",
	"EISA_DBG",
	"elantech_debug",
	"em28xx_isocdbg",
	"em28xx_regdbg",
	"em28xx_videodbg",
	"eprintf",
	"eprintk",
	"err",
	"ERR",
	"err_msg",
	"ERR_MSG",
	"error",
	"ERROR",
	"ErrorF",
	"err_printk",
	"esas2r_debug",
	"esas2r_hdebug",
	"esas2r_trace",
	"es_debug",
	"esp_dma_log",
	"esp_log_autosense",
	"esp_log_cmddone",
	"esp_log_command",
	"esp_log_datadone",
	"esp_log_datastart",
	"esp_log_disconnect",
	"esp_log_event",
	"esp_log_intr",
	"esp_log_msgin",
	"esp_log_reconnect",
	"esp_log_reset",
	"EVENT",
	"e_warn",
	"EXCEPTION",
	"EXOFS_DBGMSG",
	"EXOFS_DBGMSG2",
	"EXOFS_ERR",
	"ext2_debug",
	"ext4_debug",
	"ext4_warning",
	"ext_debug",
	"fail",
	"FAIL",
	"fatal",
	"f_dddprintk",
	"f_ddprintk",
	"f_dprintk",
	"fit_dbg",
	"fit_dbg_verbose",
	"fmdbg",
	"fmerr",
	"fmwarn",
	"fprintf",
	"F_printk",
	"gdbstub_printk",
	"gossip_err",
	"gossip_lerr",
	"g_strdup_printf",
	"gvt_dbg_cmd",
	"gvt_dbg_core",
	"gvt_dbg_el",
	"gvt_dbg_irq",
	"gvt_dbg_mm",
	"gvt_dbg_mmio",
	"gvt_dbg_render",
	"gvt_dbg_sched",
	"gvt_err",
	"hdmi_log",
	"hfi1_dbg_early",
	"hprintk",
	"HPRINTK",
	"hwc_debug",
	"hw_dbg",
	"i40iw_pr_err",
	"i40iw_pr_info",
	"i40iw_pr_warn",
	"I915_STATE_WARN",
	"IA64_MCA_DEBUG",
	"ics_panic",
	"IEEE80211_DEBUG_EAP",
	"IEEE80211_DEBUG_FRAG",
	"IEEE80211_DEBUG_MGMT",
	"IEEE80211_DEBUG_SCAN",
	"IEEE80211_DEBUG_WX",
	"IEEE80211_ERROR",
	"IF_ABR",
	"IF_CBR",
	"IF_ERR",
	"IF_EVENT",
	"IF_INIT",
	"IF_RX",
	"IF_RXPKT",
	"IF_TX",
	"IF_TXPKT",
	"IF_UBR",
	"IL_ERR",
	"IL_INFO",
	"IL_WARN",
	"imm_fail",
	"INF_MSG",
	"info",
	"INFO",
	"input_dbg",
	"intel_pt_log",
	"INTPRINTK",
	"ioapic_debug",
	"ipr_dbg",
	"ipr_err",
	"ipr_info",
	"IPRINTK",
	"ipr_trace",
	"IPW_DEBUG_ASSOC",
	"IPW_DEBUG_DROP",
	"IPW_DEBUG_ERROR",
	"IPW_DEBUG_FRAG",
	"IPW_DEBUG_FW",
	"IPW_DEBUG_FW_INFO",
	"IPW_DEBUG_HC",
	"IPW_DEBUG_INFO",
	"IPW_DEBUG_IO",
	"IPW_DEBUG_ISR",
	"IPW_DEBUG_LED",
	"IPW_DEBUG_MERGE",
	"IPW_DEBUG_NOTIF",
	"IPW_DEBUG_ORD",
	"IPW_DEBUG_QOS",
	"IPW_DEBUG_RF_KILL",
	"IPW_DEBUG_RX",
	"IPW_DEBUG_SCAN",
	"IPW_DEBUG_STATS",
	"IPW_DEBUG_TX",
	"IPW_DEBUG_WEP",
	"IPW_DEBUG_WX",
	"IPW_ERROR",
	"IPW_WARNING",
	"ir_dprintk",
	"iscsi_conn_printk",
	"iser_dbg",
	"iser_err",
	"iser_info",
	"isert_dbg",
	"isert_err",
	"isert_info",
	"isert_warn",
	"iser_warn",
	"itd_dbg",
	"itd_info",
	"ite_dbg",
	"ite_dbg_verbose",
	"IVTV_ALSA_ERR",
	"IVTV_ALSA_INFO",
	"IVTV_ALSA_WARN",
	"IVTV_DEBUG_ALSA_INFO",
	"IVTV_DEBUG_DMA",
	"IVTV_DEBUG_FILE",
	"IVTV_DEBUG_HI_DMA",
	"IVTV_DEBUG_HI_FILE",
	"IVTV_DEBUG_HI_I2C",
	"IVTV_DEBUG_HI_IRQ",
	"IVTV_DEBUG_HI_MB",
	"IVTV_DEBUG_I2C",
	"IVTV_DEBUG_INFO",
	"IVTV_DEBUG_IOCTL",
	"IVTV_DEBUG_IRQ",
	"IVTV_DEBUG_MB",
	"IVTV_DEBUG_WARN",
	"IVTV_DEBUG_YUV",
	"IVTV_ERR",
	"IVTVFB_DEBUG_INFO",
	"IVTVFB_DEBUG_WARN",
	"IVTVFB_ERR",
	"IVTVFB_INFO",
	"IVTVFB_WARN",
	"IVTV_INFO",
	"IVTV_WARN",
	"IX25DEBUG",
	"JFFS2_DEBUG",
	"JFFS2_ERROR",
	"JFFS2_NOTICE",
	"JFFS2_WARNING",
	"jfs_err",
	"jfs_info",
	"jfs_warn",
	"K1212_DEBUG_PRINTK",
	"K1212_DEBUG_PRINTK_VERBOSE",
	"kdb_printf",
	"kdcore",
	"kdebug",
	"kenter",
	"KINFO",
	"kleave",
	"kmemleak_stop",
	"kmemleak_warn",
	"kvasprintf",
	"kvm_debug",
	"kvm_debug_ratelimited",
	"kvm_err",
	"kvm_info",
	"kvm_pr_debug_ratelimited",
	"kvm_pr_err_ratelimited",
	"kvm_pr_unimpl",
	"LCONSOLE_ERROR",
	"LCONSOLE_INFO",
	"LCONSOLE_WARN",
	"ldm_crit",
	"ldm_debug",
	"ldm_error",
	"ldm_info",
	"lg_dbg",
	"lg_debug",
	"lg_err",
	"lg_reg",
	"lg_warn",
	"LIBIPW_DEBUG_DROP",
	"LIBIPW_DEBUG_FRAG",
	"LIBIPW_DEBUG_MGMT",
	"LIBIPW_DEBUG_SCAN",
	"LIBIPW_DEBUG_WX",
	"LIBIPW_ERROR",
	"LOG",
	"log_err",
	"LOG_ERROR",
	"LOG_PARSE",
	"log_print",
	"log_warn",
	"mcg_warn",
	"memblock_dbg",
	"mfc_err",
	"MG_DBG",
	"mmiotrace_printk",
	"mprintk",
	"mpsslog",
	"mtk_mdp_err",
	"mtk_v4l2_err",
	"MTS_DEBUG",
	"MTS_ERROR",
	"mv_dprintk",
	"mv_printk",
	"mxl_dbg",
	"mxl_debug",
	"mxl_debug_adv",
	"mxl_i2c",
	"mxl_info",
	"mxl_warn",
	"ncp_vdbg",
	"net_crit_ratelimited",
	"net_dbg_ratelimited",
	"netdev_printk",
	"net_err_ratelimited",
	"netif_printk",
	"net_info_ratelimited",
	"net_notice_ratelimited",
	"net_warn_ratelimited",
	"non_fatal",
	"no_printk",
	"NPRINTK",
	"NS_DBG",
	"NS_ERR",
	"NS_INFO",
	"NS_LOG",
	"NS_WARN",
	"ntfs_debug",
	"n_tty_trace",
	"numadbg",
	"nvt_dbg",
	"nvt_dbg_verbose",
	"OPRINTK",
	"ORE_DBGMSG",
	"ORE_DBGMSG2",
	"ORE_ERR",
	"OSDBLK_DEBUG",
	"OSD_DEBUG",
	"OSD_ERR",
	"OSD_INFO",
	"OSD_SENSE_PRINT1",
	"OSD_SENSE_PRINT2",
	"pair_err",
	"panic",
	"PANIC",
	"PDBG",
	"PDEBUG",
	"pdprintf",
	"PDPRINTK",
	"PERR",
	"pgd_ERROR",
	"pgprintk",
	"pid_dbg_print",
	"pk_error",
	"PM8001_EH_DBG",
	"PM8001_FAIL_DBG",
	"PM8001_IO_DBG",
	"PM8001_MSG_DBG",
	"pm8001_printk",
	"pmcraid_err",
	"pmcraid_info",
	"pmd_ERROR",
	"pmz_debug",
	"pmz_error",
	"pmz_info",
	"ppa_fail",
	"PP_DBG_LOG",
	"pr",
	"pr2",
	"pr_alert",
	"pr_alert_once",
	"pr_alert_ratelimited",
	"pr_cont",
	"pr_cont_once",
	"pr_crit",
	"pr_crit_once",
	"pr_crit_ratelimited",
	"pr_debug",
	"pr_debug2",
	"pr_debug3",
	"pr_debug4",
	"pr_debug_once",
	"pr_debug_ratelimited",
	"pr_define",
	"pr_devel",
	"PR_DEVEL",
	"pr_devel_once",
	"pr_devel_ratelimited",
	"pr_emerg",
	"pr_emerg_once",
	"pr_emerg_ratelimited",
	"pr_err",
	"pr_err_once",
	"pr_err_ratelimited",
	"pr_fmt",
	"pr_hard",
	"pr_hardcont",
	"pr_info",
	"pr_info_ipaddr",
	"pr_info_once",
	"pr_info_ratelimited",
	"print",
	"PRINT",
	"print_credit_info",
	"print_dbg",
	"PRINT_DEBUG",
	"print_err",
	"PRINT_ERR",
	"printf",
	"PRINTF",
	"printf_alert",
	"PRINT_FATAL",
	"printf_crit",
	"printf_debug",
	"printf_err",
	"printf_info",
	"printf_notice",
	"printf_warning",
	"print_info",
	"PRINT_INFO",
	"printk",
	"PRINTK",
	"PRINTK2",
	"PRINTK3",
	"printk_deferred",
	"printk_deferred_once",
	"printk_emit",
	"PRINTK_ERROR",
	"PRINTKI",
	"printk_once",
	"printk_ratelimited",
	"printl",
	"print_symbol",
	"print_warn",
	"PRINT_WARN",
	"pr_notice",
	"pr_notice_once",
	"pr_notice_ratelimited",
	"PROBE_DEBUG",
	"prom_debug",
	"prom_printf",
	"pr_stat",
	"pr_vdebug",
	"pr_warn",
	"pr_warning",
	"pr_warning_once",
	"pr_warn_once",
	"pr_warn_ratelimited",
	"PWC_DEBUG_FLOW",
	"PWC_DEBUG_IOCTL",
	"PWC_DEBUG_MEMORY",
	"PWC_DEBUG_OPEN",
	"PWC_DEBUG_PROBE",
	"PWC_DEBUG_SIZE",
	"PWC_ERROR",
	"PWC_INFO",
	"PWC_TRACE",
	"RDBG",
	"r_ddprintk",
	"r_dprintk",
	"rdsdebug",
	"reiserfs_printk",
	"riocm_error",
	"riocm_warn",
	"rl_printf",
	"rmap_printk",
	"rmcd_error",
	"rmcd_warn",
	"RPRINTK",
	"RTL_DEBUG",
	"RT_TRACE",
	"RWDEBUG",
	"RXD",
	"RXPRINTK",
	"s3c_freq_dbg",
	"s3c_freq_iodbg",
	"S3C_PMDBG",
	"SAS_DPRINTK",
	"sas_printk",
	"scmd_printk",
	"SDEBUG",
	"sdev_printk",
	"sd_printk",
	"SEQ_OPTS_PRINT",
	"seq_printf",
	"setup_early_printk",
	"shost_printk",
	"slice_dbg",
	"sm_printk",
	"snd_printd",
	"snd_printdd",
	"snd_printddd",
	"snd_printk",
	"SNIC_DBG",
	"SNIC_ERR",
	"SNIC_INFO",
	"snprintf",
	"sprintf",
	"srm_printk",
	"sr_printk",
	"ssb_cont",
	"ssb_dbg",
	"ssb_err",
	"ssb_info",
	"ssb_notice",
	"ssb_warn",
	"ssp_dbg",
	"stk1160_dbg",
	"stk1160_err",
	"stk1160_warn",
	"STK_ERROR",
	"STK_INFO",
	"st_printk",
	"str_printf",
	"swim3_dbg",
	"swim3_err",
	"swim3_info",
	"swim3_warn",
	"synth_printf",
	"tda_cal",
	"tda_dbg",
	"tda_err",
	"tda_info",
	"tda_map",
	"tda_reg",
	"tda_warn",
	"TM_DEBUG",
	"TP_printk",
	"TP_printk_btrfs",
	"tprintf",
	"TRACE",
	"TRACE2",
	"TRACE3",
	"trace_eeprom",
	"trace_firmware",
	"trace_i2c",
	"trace_printk",
	"trace_seq_printf",
	"tuner_dbg",
	"tuner_err",
	"tuner_info",
	"tuner_warn",
	"TXPRINTK",
	"udbg_printf",
	"udf_debug",
	"udf_info",
	"unpoison_pr_info",
	"unw_debug",
	"URB_DBG",
	"usbip_dbg_eh",
	"usbip_dbg_stub_rx",
	"usbip_dbg_stub_tx",
	"usbip_dbg_vhci_hc",
	"usbip_dbg_vhci_rh",
	"usbip_dbg_vhci_rx",
	"usbip_dbg_vhci_sysfs",
	"usbip_dbg_vhci_tx",
	"usnic_dbg",
	"usnic_err",
	"usnic_info",
	"v1printk",
	"v2printk",
	"v4l2_err",
	"vbi_dbg",
	"vbprintf",
	"vchiq_loud_error",
	"VCPU_TP_PRINTK",
	"vdprintf",
	"VDBG",
	"VDEB",
	"verbose",
	"verbose_debug",
	"verbose_printk",
	"vfprintf",
	"video_dbg",
	"vmci_ioctl_err",
	"vpr_info",
	"vprintf",
	"vprintk",
	"VPRINTK",
	"vprintk_emit",
	"vsnprintf",
	"vsprintf",
	"warn",
	"WARN",
	"warning",
	"WARNING",
	"WARN_ON",
	"WARN_ONCE",
	"WARN_ON_ONCE",
	"warnx",
	"wcn36xx_err",
	"wcn36xx_info",
	"wcn36xx_warn",
	"wl1251_error",
	"wl1251_info",
	"wl1251_warning",
	"wl1271_error",
	"wl1271_info",
	"wl1271_notice",
	"wl1271_warning",
	"WRN_MSG",
	"xen_raw_printk",
	"XICS_DBG",
	"xip_cpu_idle",
	"XPRINTK",
	"XXDEBUG",
	"YYFPRINTF",
	"zconf_error"
};

/*
 *  djb2a()
 *	relatively fast string hash
 */
static inline uint32_t HOT djb2a(const char *str)
{
        register uint32_t c;
        register uint32_t hash = 5381;

        while (LIKELY(c = *str++))
                hash = (hash * 33) ^ c;

        return hash & HASH_MASK;
}

static int parse_file(char *restrict path, token_t *restrict t, token_t *restrict line, token_t *restrict str);

static void NORETURN out_of_memory(void)
{
	asm ("");	/* Stops inlining */
	fprintf(stderr, "Out of memory performing an allocation\n");
	exit(EXIT_FAILURE);
}

static void free_word_node(word_node_t *node, const bool do_free)
{
	size_t i;

	if (UNLIKELY(!node))
		return;

	for (i = 0; i < MAX_WORD_NODES; i++)
		free_word_node(node->nodes[i], true);

	if (LIKELY(do_free))
		free(node);
}

static void free_words(void)
{
	free_word_node(&word_nodes, false);
}

static inline void HOT add_word(char *restrict str, word_node_t *restrict node)
{
	register int ch = *str;
	word_node_t **new_node;

	if (UNLIKELY(!isalpha(ch))) {
		node->eow = true;
		return;
	}

	ch = tolower(ch) - 'a';
	new_node = &node->nodes[ch];
	if (*new_node == NULL) {
		*new_node = calloc(1, sizeof(word_node_t));
		if (UNLIKELY(!*new_node))
			out_of_memory();
	}
	add_word(++str, *new_node);
}

static int read_dictionary(const char *dict)
{
	char buffer[1024];
	FILE *fp = fopen(dict, "r");
	if (!fp)
		return -1;

	while (fgets(buffer, sizeof(buffer), fp))
		add_word(buffer, &word_nodes);
	(void)fclose(fp);

	return 0;
}

static inline int HOT find_word(const char *restrict word, const word_node_t *restrict node)
{
	for (;;) {
		register int ch;

		if (UNLIKELY(!node))
			return 0;
		ch = *word;
		if (!ch)
			return node->eow;
		if (UNLIKELY(!isalpha(ch)))
			return 1;
		ch = tolower(ch) - 'a';
		node = node->nodes[ch];
		word++;
	}
}

static inline void HOT add_bad_spelling(const char *word)
{
	register const unsigned int h = djb2a(word);
	register hash_entry_t *he = hash_bad_spellings[h];

	while (he) {
		if (!strcmp(he->token, word))
			return;
		he = he->next;
	}
	he = malloc(sizeof(*he));
	if (UNLIKELY(he == NULL))
		out_of_memory();

	he->token = strdup(word);
	if (UNLIKELY(he->token == NULL))
		out_of_memory();
	he->next = hash_bad_spellings[h];
	hash_bad_spellings[h] = he;
	bad_spellings++;
}

static void HOT check_words(char *line)
{
	register char *p1 = line, *p2, *p3;

	p3 = line + strlen(line);

	while (p1 < p3) {
		/* skip non-alhabetics */
		while (*p1 && !isalpha(*p1))
			p1++;
		if (!*p1)
			return;
		p2 = p1;
		//while (LIKELY((*p2 && (isalnum(*p2) || *p2 == '_'))))
		while (LIKELY((*p2 && (isalpha(*p2)))))
			p2++;
		*p2 = '\0';

		if (LIKELY(p2 - p1 > 1)) {
			if (!find_word(p1, &word_nodes))
				add_bad_spelling(p1);
		}
		p1 = p2 + 1;
	}
	return;
}

/*
 *  gettime_to_double()
 *      get time as a double
 */
static double gettime_to_double(void)
{
	struct timeval tv;

	if (UNLIKELY(gettimeofday(&tv, NULL) < 0))
		return 0.0;

	return (double)tv.tv_sec + ((double)tv.tv_usec / 1000000);
}

/*
 *  Initialise the parser
 */
static inline HOT void parser_new(
	parser_t *restrict p,
	unsigned char *restrict data,
	unsigned char *restrict data_end,
	const bool skip_white_space)
{
	p->data = data;
	p->data_end = data_end;
	p->ptr = data;
	p->skip_white_space = skip_white_space;
}

/*
 *  Get next character from input stream
 */
static inline int HOT get_char(parser_t *p)
{
	if (LIKELY(p->ptr < p->data_end)) {
		return *(p->ptr++);
	} else
		return PARSER_EOF;
}

/*
 *  Push character back onto the input
 *  stream (in this case, it is a simple FIFO stack
 */
static inline void HOT unget_char(parser_t *p)
{
	if (LIKELY(p->ptr > p->data))
		p->ptr--;
}

static int cmp_format(const void *p1, const void *p2)
{
	format_t *f1 = (format_t *)p1;
	format_t *f2 = (format_t *)p2;

	register const size_t l1 = f1->len;
	register const size_t l2 = f2->len;

	if (l1 < l2)
		return 1;
	if (l1 > l2)
		return -1;
	return strcmp(f1->format, f2->format);
}

/*
 *  Get length of token
 */
static inline size_t HOT token_len(token_t *t)
{
	return t->ptr - t->token;
}

/*
 *  Clear the token ready for re-use
 */
static inline void HOT token_clear(token_t *t)
{
	t->ptr = t->token;
	t->token_end = t->token + t->len;
	t->type = TOKEN_UNKNOWN;
	*(t->ptr) = '\0';
}

/*
 *  Create a new token, give it plenty of slop so
 *  we don't need to keep on reallocating the token
 *  buffer as we append more characters to it during
 *  the lexing phase.
 */
static void token_new(token_t *t)
{
	t->token = calloc(TOKEN_CHUNK_SIZE, 1);
	if (UNLIKELY(t->token == NULL))
		out_of_memory();
	t->len = TOKEN_CHUNK_SIZE;
	token_clear(t);
}

/*
 *  Free the token
 */
static void token_free(token_t *t)
{
	free(t->token);
	t->ptr = NULL;
	t->token = NULL;
	t->token_end = NULL;
	t->len = 0;
}

static void HOT token_expand(token_t *t)
{
	/* No more space, add 1K more space */
	ptrdiff_t diff = t->ptr - t->token;

	t->len += TOKEN_CHUNK_SIZE;
	t->token_end += TOKEN_CHUNK_SIZE;
	t->token = realloc(t->token, t->len);
	if (UNLIKELY(t->token == NULL))
		out_of_memory();
	t->ptr = t->token + diff;
}

/*
 *  Append a single character to the token,
 *  we may run out of space, so this occasionally
 *  adds an extra 1K of token space for long tokens
 */
static inline void HOT token_append(token_t *t, const int ch)
{
	if (UNLIKELY(t->ptr >= (t->token_end)))
		token_expand(t);

	/* Enough space, just add char */
	*(t->ptr++) = ch;
}

static inline void HOT token_eos(token_t *t)
{
	*(t->ptr) = '\0';
}

static inline void HOT token_cat_str(token_t *restrict t, const char *restrict str)
{
	while (*str) {
		token_append(t, *str);
		str++;
	}
	token_eos(t);
}

static int skip_macros(parser_t *p)
{
	bool continuation = false;

	for (;;) {
		register int ch;

		ch = get_char(p);
		if (UNLIKELY(ch == PARSER_EOF))
			break;
		if (ch == '\n') {
			lines++;
			lineno++;
			if (!continuation)
				return ch;
			continuation = false;
		} else if (ch == '\\') {
			continuation = true;
		}
	}
	return PARSER_EOF;
}

/*
 *  Parse C comments and just throw them away
 */
static int skip_comments(parser_t *p)
{
	register int ch;
	int nextch;

	nextch = get_char(p);
	if (UNLIKELY(nextch == PARSER_EOF))
		return nextch;

	if (nextch == '/') {
		do {
			ch = get_char(p);
			if (UNLIKELY(ch == PARSER_EOF))
				return ch;
		} while (ch != '\n');

		return PARSER_COMMENT_FOUND;
	}

	if (LIKELY(nextch == '*')) {
		for (;;) {
			ch = get_char(p);
			if (UNLIKELY(ch == PARSER_EOF))
				return ch;

			if (UNLIKELY(ch == '*')) {
				ch = get_char(p);
				if (UNLIKELY(ch == PARSER_EOF))
					return ch;

				if (LIKELY(ch == '/'))
					return PARSER_COMMENT_FOUND;

				unget_char(p);
			}
		}
	}

	/* Not a comment, push back */
	unget_char(p);

	return PARSER_OK;
}

/*
 *  Parse an integer.  This is fairly minimal as the
 *  kernel doesn't have floats or doubles, so we
 *  can just parse decimal, octal or hex values.
 */
static int parse_number(parser_t *restrict p, token_t *restrict t, int ch)
{
	bool ishex = false;
	bool isoct = false;

	/*
	 *  Crude way to detect the kind of integer
	 */
	if (ch == '0') {
		int nextch1, nextch2;

		token_append(t, ch);

		nextch1 = get_char(p);
		if (UNLIKELY(nextch1 == PARSER_EOF)) {
			token_append(t, ch);
			token_eos(t);
			return PARSER_OK;
		}

		if (nextch1 >= '0' && nextch1 <= '8') {
			/* Must be an octal value */
			ch = nextch1;
			isoct = true;
		} else if (nextch1 == 'x' || nextch1 == 'X') {
			/* Is it hexadecimal? */
			nextch2 = get_char(p);
			if (UNLIKELY(nextch2 == PARSER_EOF)) {
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}

			if (isxdigit(nextch2)) {
				/* Hexadecimal */
				token_append(t, nextch1);
				ch = nextch2;
				ishex = true;
			} else {
				/* Nope */
				unget_char(p);
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}
		} else {
			unget_char(p);
			token_eos(t);
			return PARSER_OK;
		}
	}

	/*
	 * OK, we now know what type of integer we
	 * are processing, so just gather up the digits
	 */
	token_append(t, ch);

	for (;;) {
		ch = get_char(p);

		if (UNLIKELY(ch == PARSER_EOF)) {
			unget_char(p);
			token_eos(t);
			return PARSER_OK;
		}

		if (ishex) {
			if (LIKELY(isxdigit(ch))) {
				token_append(t, ch);
			} else {
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}
		} else if (isoct) {
			if (LIKELY(ch >= '0' && ch <= '8')) {
				token_append(t, ch);
			} else {
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}
		} else {
			if (isdigit(ch)) {
				token_append(t, ch);
			} else {
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}
		}
	}
}

/*
 *  Parse identifiers
 */
static int HOT parse_identifier(parser_t *restrict p, token_t *restrict t, int ch)
{
	t->type = TOKEN_IDENTIFIER;
	token_append(t, ch);

	for (;;) {
		ch = get_char(p);
		if (LIKELY(isalnum(ch) || UNLIKELY(ch == '_'))) {
			token_append(t, ch);
			continue;
		}

		unget_char(p);
		token_eos(t);
		return PARSER_OK;
	}
}

/*
 *  Parse literal strings
 */
static int parse_literal(
	parser_t *restrict p,
	token_t *restrict t,
	const int literal,
	const token_type_t type)
{
	t->type = type;

	token_append(t, literal);

	for (;;) {
		int ch = get_char(p);
		if (UNLIKELY(ch == PARSER_EOF)) {
			token_eos(t);
			return PARSER_OK;
		}

		if (ch == '\\') {
			if (opt_flags & OPT_ESCAPE_STRIP) {
				ch = get_char(p);
				if (UNLIKELY(ch == PARSER_EOF)) {
					token_eos(t);
					return ch;
				}
				switch (ch) {
				case '?':
					token_append(t, ch);
					continue;
				case 'a':
				case 'b':
				case 'f':
				case 'n':
				case 'r':
				case 't':
				case 'v':
					ch = get_char(p);
					unget_char(p);
					if (ch != literal)
						token_append(t, ' ');
					continue;
				case 'x':
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '9':
				default:
					token_append(t, '\\');
					token_append(t, ch);
					continue;
				}
			} else {
				token_append(t, ch);
				ch = get_char(p);
				if (UNLIKELY(ch == PARSER_EOF)) {
					token_eos(t);
					return ch;
				}
				token_append(t, ch);
				continue;
			}
		}

		if (UNLIKELY(ch == literal)) {
			token_append(t, ch);
			token_eos(t);
			return PARSER_OK;
		}

		token_append(t, ch);
	}
	token_eos(t);

	return PARSER_OK;
}

/*
 *  Parse operators such as +, - which can
 *  be + or ++ forms.
 */
static inline int parse_op(parser_t *restrict p, token_t *restrict t, int op)
{
	int ch;

	token_append(t, op);

	ch = get_char(p);

	if (ch == op) {
		token_append(t, op);
		token_eos(t);
		return PARSER_OK;
	}

	unget_char(p);
	token_eos(t);
	return PARSER_OK;
}

/*
 *  Parse -, --, ->
 */
static inline int parse_minus(parser_t *restrict p, token_t *restrict t, int op)
{
	int ch;

	token_append(t, op);

	ch = get_char(p);

	if (ch == op) {
		token_append(t, ch);
		token_eos(t);
		return PARSER_OK;
	}

	if (ch == '>') {
		token_append(t, ch);
		token_eos(t);
		t->type = TOKEN_ARROW;
		return PARSER_OK;
	}

	unget_char(p);
	token_eos(t);
	return PARSER_OK;
}

static inline int parse_skip_comments(parser_t *restrict p, token_t *restrict t, int ch)
{
	int ret = skip_comments(p);

	if (UNLIKELY(ret == PARSER_EOF))
		return ret;

	if (ret == PARSER_COMMENT_FOUND) {
		ret |= PARSER_CONTINUE;
		return ret;
	}
	token_append(t, ch);
	token_eos(t);
	return PARSER_OK;
}

static inline int parse_simple(token_t *t, int ch, token_type_t type)
{
	token_append(t, ch);
	token_eos(t);
	t->type = type;
	return PARSER_OK;
}

static inline int parse_hash(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;
	(void)ch;

	skip_macros(p);
	token_clear(t);

	return PARSER_OK;
}

static inline int parse_paren_opened(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_PAREN_OPENED);
}

static inline int parse_paren_closed(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_PAREN_CLOSED);
}


static inline int parse_square_opened(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_SQUARE_OPENED);
}

static inline int parse_square_closed(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_SQUARE_CLOSED);
}

static inline int parse_less_than(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_LESS_THAN);
}

static inline int parse_greater_than(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_GREATER_THAN);
}

static inline int parse_comma(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_COMMA);
}

static inline int parse_terminal(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_TERMINAL);
}

static inline int parse_misc_char(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;

	token_append(t, ch);
	token_eos(t);
	return PARSER_OK;
}

static inline int parse_literal_string(parser_t *restrict p, token_t *restrict t, int ch)
{
	return parse_literal(p, t, ch, TOKEN_LITERAL_STRING);
}

static inline int parse_literal_char(parser_t *restrict p, token_t *restrict t, int ch)
{
	return parse_literal(p, t, ch, TOKEN_LITERAL_CHAR);
}

static inline int parse_backslash(parser_t *restrict p, token_t *restrict t, int ch)
{
	if (p->skip_white_space)
		return PARSER_OK | PARSER_CONTINUE;

	if (opt_flags & OPT_ESCAPE_STRIP) {
		token_append(t, ch);
		token_eos(t);
		t->type = TOKEN_WHITE_SPACE;
	} else {
		token_append(t, ch);
		ch = get_char(p);
		if (UNLIKELY(ch == PARSER_EOF))
			return ch;
		token_append(t, ch);
		token_eos(t);
	}
	return PARSER_OK;
}

static inline int parse_newline(parser_t *restrict p, token_t *restrict t, int ch)
{
	lines++;
	lineno++;
	return parse_backslash(p, t, ch);
}

static inline int parse_eof(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;
	(void)t;
	(void)ch;

	return PARSER_EOF;
}

static inline int parse_whitespace(parser_t *restrict p, token_t *restrict t, int ch)
{
	(void)p;
	(void)ch;

	t->type = TOKEN_IDENTIFIER;
	token_append(t, ch);

	for (;;) {
		ch = get_char(p);
		if (ch != ' ' && ch != '\t') {
			break;
		}
	}
	unget_char(p);
	token_eos(t);

	return parse_simple(t, ' ', TOKEN_WHITE_SPACE);
}

static get_token_action_t get_token_actions[] = {
	['/'] = parse_skip_comments,
	['#'] = parse_hash,
	['('] = parse_paren_opened,
	[')'] = parse_paren_closed,
	['['] = parse_square_opened,
	[']'] = parse_square_closed,
	['<'] = parse_less_than,
	['>'] = parse_greater_than,
	[','] = parse_comma,
	[';'] = parse_terminal,
	['{'] = parse_misc_char,
	['}'] = parse_misc_char,
	[':'] = parse_misc_char,
	['~'] = parse_misc_char,
	['?'] = parse_misc_char,
	['*'] = parse_misc_char,
	['%'] = parse_misc_char,
	['!'] = parse_misc_char,
	['.'] = parse_misc_char,
	['0'] = parse_number,
	['1'] = parse_number,
	['2'] = parse_number,
	['3'] = parse_number,
	['4'] = parse_number,
	['5'] = parse_number,
	['6'] = parse_number,
	['7'] = parse_number,
	['8'] = parse_number,
	['9'] = parse_number,
	['+'] = parse_op,
	['='] = parse_op,
	['|'] = parse_op,
	['&'] = parse_op,
	['-'] = parse_minus,
	['a'] = parse_identifier,
	['b'] = parse_identifier,
	['c'] = parse_identifier,
	['d'] = parse_identifier,
	['e'] = parse_identifier,
	['f'] = parse_identifier,
	['g'] = parse_identifier,
	['h'] = parse_identifier,
	['i'] = parse_identifier,
	['j'] = parse_identifier,
	['k'] = parse_identifier,
	['l'] = parse_identifier,
	['m'] = parse_identifier,
	['n'] = parse_identifier,
	['o'] = parse_identifier,
	['p'] = parse_identifier,
	['q'] = parse_identifier,
	['r'] = parse_identifier,
	['s'] = parse_identifier,
	['t'] = parse_identifier,
	['u'] = parse_identifier,
	['v'] = parse_identifier,
	['w'] = parse_identifier,
	['x'] = parse_identifier,
	['y'] = parse_identifier,
	['z'] = parse_identifier,
	['A'] = parse_identifier,
	['B'] = parse_identifier,
	['C'] = parse_identifier,
	['D'] = parse_identifier,
	['E'] = parse_identifier,
	['F'] = parse_identifier,
	['G'] = parse_identifier,
	['H'] = parse_identifier,
	['I'] = parse_identifier,
	['J'] = parse_identifier,
	['K'] = parse_identifier,
	['L'] = parse_identifier,
	['M'] = parse_identifier,
	['N'] = parse_identifier,
	['O'] = parse_identifier,
	['P'] = parse_identifier,
	['Q'] = parse_identifier,
	['R'] = parse_identifier,
	['S'] = parse_identifier,
	['T'] = parse_identifier,
	['U'] = parse_identifier,
	['V'] = parse_identifier,
	['W'] = parse_identifier,
	['X'] = parse_identifier,
	['Y'] = parse_identifier,
	['Z'] = parse_identifier,
	['"'] = parse_literal_string,
	['\''] = parse_literal_char,
	['\\'] = parse_backslash,
	['\n'] = parse_newline,
	[' '] = parse_whitespace,
	['\t'] = parse_whitespace,
	[PARSER_EOF] = parse_eof,
};


/*
 *  Gather a token from input stream
 */
static int HOT get_token(parser_t *restrict p, token_t *restrict t)
{
	for (;;) {
		register int ch = get_char(p);
		register get_token_action_t action = get_token_actions[ch];
		register int ret;

		if (UNLIKELY(!action))
			continue;

		ret = action(p, t, ch);
		if (UNLIKELY(ret & PARSER_CONTINUE))
			continue;
		return ret;
	}

	return PARSER_OK;
}

/*
 *  Literals such as "foo" and 'f' sometimes
 *  need the quotes stripping off.
 */
static inline void literal_strip_quotes(token_t *t)
{
	size_t len = token_len(t);

	t->token[len - 1] = '\0';

	__builtin_memmove(t->token, t->token + 1, len - 1);

	t->ptr -= 2;
}

/*
 *  Concatenate new string onto old. The old
 *  string can be NULL or an existing string
 *  on the heap.  This returns the newly
 *  concatenated string.
 */
static void token_cat_normal(
	token_t *restrict token,
	token_t *restrict token_to_add)
{
	token_cat_str(token, token_to_add->token);
}

/*
 *  Concatenate new string onto old. The old
 *  string can be NULL or an existing string
 *  on the heap.  This returns the newly
 *  concatenated string.
 */
static void token_cat_just_literal_string(
	token_t *restrict token,
	token_t *restrict token_to_add)
{
	if (token_to_add->type == TOKEN_LITERAL_STRING)
		token_cat_str(token, token_to_add->token);
}

static void strip_format(char *line)
{
	char *ptr1 = line, *ptr2 = line;

	while (*ptr1) {
		if (UNLIKELY((*ptr1 == '%') && *(ptr1 + 1))) {
			size_t i;

			*ptr2++ = ' ';
			ptr1++;
			if (*ptr1 == '-')
				ptr1++;
			while (isdigit(*ptr1) || *ptr1 == '.')
				ptr1++;

			for (i = 0; i < SIZEOF_ARRAY(formats); i++) {
				register const size_t len = formats[i].len;

				if (UNLIKELY(!strncmp(formats[i].format, ptr1, len))) {
					ptr1 += len;
					break;
				}
			}
		} else {
			*ptr2++ = *ptr1++;
		}
	}
	*ptr2 = '\0';
}

/*
 *  Parse a kernel message, like printk() or dev_err()
 */
static int parse_kernel_message(
	const char *restrict path,
	bool *restrict source_emit,
	parser_t *restrict p,
	token_t *restrict t,
	token_t *restrict line,
	token_t *restrict str)
{
	bool got_string = false;
	bool emit = false;
	bool found = false;
	bool nl = false;
	bool check_nl = ((opt_flags & OPT_MISSING_NEWLINE) != 0);

	token_clear(line);

	token_cat(line, t);
	token_clear(t);
	if (UNLIKELY(get_token(p, t) == PARSER_EOF)) {
		return PARSER_EOF;
	}
	if (t->type != TOKEN_PAREN_OPENED) {
		for (;;) {
			if (UNLIKELY(get_token(p, t) == PARSER_EOF))
				return PARSER_EOF;
			if (t->type == TOKEN_TERMINAL)
				break;
		}
		token_clear(t);
		return PARSER_OK;
	}
	token_cat(line, t);
	token_clear(t);

	token_clear(str);
	for (;;) {
		int ret = get_token(p, t);

		if (UNLIKELY(ret == PARSER_EOF))
			return PARSER_EOF;

		/*
		 *  Hit ; so lets push out what we've parsed
		 */
		if (t->type == TOKEN_TERMINAL) {
			if (check_nl & nl) {
				emit = false;
			}
			if (emit) {
				if (opt_flags & OPT_CHECK_WORDS)
					check_words(line->token);
				else {
					if (! *source_emit) {
						if (opt_flags & OPT_SOURCE_NAME)
							printf("Source: %s\n", path);
						*source_emit = true;
					}
					if (opt_flags & OPT_FORMAT_STRIP)
						strip_format(line->token);
					printf("%s%s", line->token,
						(opt_flags & OPT_LITERAL_STRINGS) ? "" : ";");
					printf("\n");
				}
				finds++;
			}
			token_clear(t);
			return PARSER_OK;
		}

		if (t->type == TOKEN_LITERAL_STRING) {
			literal_strip_quotes(t);
			token_cat(str, t);

			if (!got_string)
				token_cat_str(line, quotes);

			got_string = true;
			emit = true;
		} else {
			if (got_string) {
				size_t len = token_len(line);

				if ((check_nl) &&
				    (len > 2) &&
				    (line->token[len - 3] == '\\') &&
				    (line->token[len - 2] == 'n')) {
					nl = true;
				}
				token_cat_str(line, quotes);
			}
			got_string = false;

			if (token_len(str)) {
				found |= true;
				token_clear(str);
			}
		}

		token_cat(line, t);
		if (t->type == TOKEN_COMMA)
			token_cat_str(line, space);

		token_clear(t);
	}
}

/*
 *  Parse input looking for printk or dev_err calls
 */
static void parse_kernel_messages(
	const char *restrict path,
	unsigned char *restrict data,
	unsigned char *restrict data_end,
	token_t *restrict t,
	token_t *restrict line,
	token_t *restrict str)
{
	parser_t p;

	parser_new(&p, data, data_end, true);
	bool source_emit = false;

	token_clear(t);

	while ((get_token(&p, t)) != PARSER_EOF) {
		register unsigned int h = djb2a(t->token);
		hash_entry_t *hf = hash_printks[h];

		while (hf) {
			if (!__builtin_strcmp(t->token, hf->token)) {
				parse_kernel_message(path, &source_emit, &p, t, line, str);
				break;
			}
			hf = hf->next;
		}
		token_clear(t);
	}

	if (source_emit && (opt_flags & OPT_SOURCE_NAME))
		putchar('\n');
}

static void show_usage(void)
{
	fprintf(stderr, "kernelscan: the fast kernel source message scanner\n\n");
	fprintf(stderr, "kernelscan [options] path\n");
	fprintf(stderr, "  -c     check words in dictionary\n");
	fprintf(stderr, "  -e     strip out C escape sequences\n");
	fprintf(stderr, "  -f     replace kernel %% format specifiers with a space\n");
	fprintf(stderr, "  -h     show this help\n");
	fprintf(stderr, "  -n     find messages with missing \\n newline\n");
	fprintf(stderr, "  -s     just print literal strings\n");
	fprintf(stderr, "  -x     exclude the source file name from the output\n");
}

static int parse_dir(
	char *restrict path,
	token_t *restrict t,
	token_t *restrict line,
	token_t *restrict str)
{
	DIR *dp;
	struct dirent *d;
	char filepath[PATH_MAX];
	register char *ptr1, *ptr2;

	if (UNLIKELY((dp = opendir(path)) == NULL)) {
		fprintf(stderr, "Cannot open directory %s, errno=%d (%s)\n",
			path, errno, strerror(errno));
		return -1;
	}

	ptr1 = filepath;
	ptr2 = path;

	while ((*ptr1 = *(ptr2++)))
		ptr1++;

	*ptr1++ = '/';

	while ((d = readdir(dp)) != NULL) {
		struct stat buf;
		register char *ptr;

		if (UNLIKELY(d->d_name[0] == '.'))
			continue;

		ptr = ptr1;
		ptr2 = d->d_name;
		while ((*ptr = *(ptr2++)))
			ptr++;
		*ptr = '\0';

		if (lstat(filepath, &buf) < 0)
			continue;
		/* Don't follow symlinks */
		if (S_ISLNK(buf.st_mode))
			continue;
		parse_file(filepath, t, line, str);
	}
	(void)closedir(dp);

	return 0;
}

static int HOT parse_file(
	char *restrict path,
	token_t *restrict t,
	token_t *restrict line,
	token_t *restrict str)
{
	struct stat buf;
	int fd;
	int rc = 0;

	fd = open(path, O_RDONLY);
	if (UNLIKELY(fd < 0)) {
		fprintf(stderr, "Cannot open %s, errno=%d (%s)\n",
			path, errno, strerror(errno));
		return -1;
	}
	if (UNLIKELY(fstat(fd, &buf) < 0)) {
		fprintf(stderr, "Cannot stat %s, errno=%d (%s)\n",
			path, errno, strerror(errno));
		(void)close(fd);
		return -1;
	}
	lineno = 0;

	if (LIKELY(S_ISREG(buf.st_mode))) {
		size_t len = __builtin_strlen(path);

		if (LIKELY(((len >= 2) && !__builtin_strcmp(path + len - 2, ".c")) ||
		    ((len >= 2) && !__builtin_strcmp(path + len - 2, ".h")) ||
		    ((len >= 4) && !__builtin_strcmp(path + len - 4, ".cpp")))) {
			if (LIKELY(buf.st_size > 0)) {
				unsigned char *data = mmap(NULL, (size_t)buf.st_size, PROT_READ,
					MAP_PRIVATE | MAP_POPULATE, fd, 0);
				if (UNLIKELY(data == MAP_FAILED)) {
					(void)close(fd);
					fprintf(stderr, "Cannot mmap %s, errno=%d (%s)\n",
						path, errno, strerror(errno));
					return -1;
				}
				__builtin_prefetch(data, 0, 1);
				parse_kernel_messages(path, data, data + buf.st_size, t, line, str);
				(void)munmap(data, (size_t)buf.st_size);
			}
			files++;
		}
		(void)close(fd);
	} else {
		(void)close(fd);
		if (S_ISDIR(buf.st_mode))
			rc = parse_dir(path, t, line, str);
	}
	return rc;
}

static int cmpstr(const void *p1, const void *p2)
{
	return strcmp(* (char * const *) p1, * (char * const *) p2);
}

static void dump_bad_spellings(void)
{
	size_t i, j;
	char **bad_spellings_sorted;

	bad_spellings_sorted = calloc(bad_spellings, sizeof(char *));
	if (!bad_spellings_sorted)
		out_of_memory();

	for (i = 0, j = 0; i < SIZEOF_ARRAY(hash_bad_spellings); i++) {
		hash_entry_t *he = hash_bad_spellings[i];

		while (he) {
			hash_entry_t *next = he->next;
			bad_spellings_sorted[j++] = he->token;

			free(he);
			he = next;
		}
	}

	qsort(bad_spellings_sorted, j, sizeof(char *), cmpstr);

	for (i = 0; i < bad_spellings; i++) {
		printf("%s\n", bad_spellings_sorted[i]);
		free(bad_spellings_sorted[i]);
	}

	free(bad_spellings_sorted);
}

/*
 *  Scan kernel source for printk like statements
 */
int main(int argc, char **argv)
{
	size_t i;
	token_t t, line, str;
	double t1, t2;
	hash_entry_t he_table[SIZEOF_ARRAY(printks)];
	hash_entry_t *he = he_table;

	token_cat = token_cat_normal;

	for (;;) {
		int c = getopt(argc, argv, "cefhnsx");
		if (c == -1)
 			break;
		switch (c) {
		case 'c':
			opt_flags |= OPT_CHECK_WORDS;
			break;
		case 'e':
			opt_flags |= OPT_ESCAPE_STRIP;
			break;
		case 'f':
			opt_flags |= OPT_FORMAT_STRIP;
			break;
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'n':
			opt_flags |= OPT_MISSING_NEWLINE;
			break;
		case 's':
			opt_flags |= OPT_LITERAL_STRINGS;
			token_cat = token_cat_just_literal_string;
			break;
		case 'x':
			opt_flags &= ~OPT_SOURCE_NAME;
			break;
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	(void)qsort(formats, SIZEOF_ARRAY(formats), sizeof(format_t), cmp_format);
	if (opt_flags & OPT_CHECK_WORDS)
		(void)read_dictionary("/usr/share/dict/words");

	for (i = 0; i < SIZEOF_ARRAY(printks); i++) {
		register const unsigned int h = djb2a(printks[i]);

		he->token = printks[i];
		he->next = hash_printks[h];
		hash_printks[h] = he;
		he++;
	}

	token_new(&t);
	token_new(&line);
	token_new(&str);

	t1 = gettime_to_double();
	while (argc > optind) {
		parse_file(argv[optind], &t, &line, &str);
		optind++;
	}
	t2 = gettime_to_double();

	token_free(&str);
	token_free(&line);
	token_free(&t);

	dump_bad_spellings();
	free_words();

	printf("\n%" PRIu32 " files scanned\n", files);
	printf("%" PRIu32 " lines scanned\n", lines);
	printf("%" PRIu32 " print statements found\n", finds);
	if (bad_spellings)
		printf("%" PRIu32 " bad spellings found\n", bad_spellings);
	printf("scanned %.2f lines per second\n", 
		FLOAT_CMP(t1, t2) ? 0.0 : (double)lines / (t2 - t1));
	printf("(kernelscan " VERSION ")\n");

	exit(EXIT_SUCCESS);
}
