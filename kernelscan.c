/*
 * Copyright (C) 2012-2019 Canonical
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
#define _GNU_SOURCE

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
#include <sys/wait.h>
#include <fcntl.h>
#include <mqueue.h>
#include <signal.h>
#include <pthread.h>
#if defined(__linux__)
#include <linux/types.h>
#endif

#define OPT_ESCAPE_STRIP	0x00000001
#define OPT_MISSING_NEWLINE	0x00000002
#define OPT_LITERAL_STRINGS	0x00000004
#define OPT_SOURCE_NAME		0x00000008
#define OPT_FORMAT_STRIP	0x00000010
#define OPT_CHECK_WORDS		0x00000020
#define OPT_PARSE_STRINGS	0x00000040

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

#define MAX_WORD_NODES		(27)	/* a..z -> 0..25 and _/0..9 as 26 */
#define WORD_NODES_HEAP_SIZE	(250000)
#define PRINTK_NODES_HEAP_SIZE	(12000)
#define SIZEOF_ARRAY(x)		(sizeof(x) / sizeof(x[0]))

#define BAD_MAPPING		(0xff)

//#define PACKED_INDEX		(0)

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

#if defined(__GNUC__) && NEED_GNUC(4,6,0)
#define PACKED	__attribute__((packed))
#else
#define PACKED
#endif

#if defined(__GNUC__) && NEED_GNUC(3,4,0)
/* #define PURE	__attribute__((pure)) */
#define PURE
#else
#define PURE
#endif

#if defined(__GNUC__) && NEED_GNUC(3,4,0)
#define CONST	__attribute__((const))
#else
#define CONST
#endif

#if defined(__GNUC__) && NEED_GNUC(3,3,0)
#define ALIGNED(a)	__attribute__((aligned(a)))
#endif

/* GCC5.0+ target_clones attribute */
#if defined(__GNUC__) && NEED_GNUC(5,5,0) && STRESS_X86 && \
    !defined(__gnu_hurd__) && !defined(__FreeBSD_Kernel__)
#define TARGET_CLONES   __attribute__((target_clones("sse","sse2","ssse3", "sse4.1", "sse4a", "avx","avx2","default")))
#else
#define TARGET_CLONES
#endif

#if defined(__GNUC__) || defined(__clang__)
#define RESTRICT __restrict
#else
#define RESTRICT
#endif

static const char dictionary[] = "/usr/share/dict/american-english";

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

typedef void (*parse_func_t)(
        const char *RESTRICT path,
        unsigned char *RESTRICT data,
        unsigned char *RESTRICT data_end,
        token_t *RESTRICT t,
        token_t *RESTRICT line,
        token_t *RESTRICT str);

typedef uint16_t get_char_t;

typedef struct {
	void		*data;
	size_t		size;
	parse_func_t	parse_func;
	char		filename[PATH_MAX];
} msg_t;

typedef struct {
	char *path;
	mqd_t mq;
} context_t;

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
	char token[0];
} hash_entry_t;

typedef get_char_t (*get_token_action_t)(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch);

/*
 *  printk format string table items
 */
typedef struct {
	char *format;	/* printk format string */
	size_t len;	/* length of format string */
} format_t;

#if defined PACKED_INDEX
typedef struct {
	uint8_t	 hi8;
	uint16_t lo16;
} PACKED index_t;
#else
typedef struct {
	uint32_t lo32;
} index_t;
#endif

typedef struct word_node {
	index_t		word_node_index[MAX_WORD_NODES];
	bool		eow;	/* End of Word flag */
} PACKED word_node_t ;

static uint64_t bytes_total;
static uint32_t finds;
static uint32_t files;
static uint32_t lines;
static uint32_t lineno;
static uint32_t bad_spellings;
static uint32_t bad_spellings_total;
static uint32_t words;
static uint32_t dict_size;

static uint8_t opt_flags = OPT_SOURCE_NAME;
static void (*token_cat)(token_t *RESTRICT token, token_t *RESTRICT token_to_add);
static char quotes[] = "\"";
static char space[] = " ";
static bool is_not_whitespace[256] ALIGNED(64);
static bool is_not_identifier[256] ALIGNED(64);

/*
 *  flat tree of dictionary words
 */
static word_node_t word_node_heap[WORD_NODES_HEAP_SIZE];
static word_node_t *word_nodes = &word_node_heap[0];
static word_node_t *word_node_heap_next = &word_node_heap[1];

/*
 *  flat tree of printk like function names
 */
static word_node_t printk_node_heap[PRINTK_NODES_HEAP_SIZE];
static word_node_t *printk_nodes = &printk_node_heap[0];
static word_node_t *printk_node_heap_next = &printk_node_heap[1];

/*
 *  hash table of bad spellings
 */
static hash_entry_t *hash_bad_spellings[TABLE_SIZE];

/*
 *  Kernel printk format specifiers
 */
static format_t formats[] ALIGNED(64) = {
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
 *  various printk like functions to populate the
 *  hash_printks hash table
 */
static char *printks[] = {
	"AA_BUG",
	"AA_DEBUG",
	"AA_ERROR",
	"aa_info_message",
	"ABIT_UGURU3_DEBUG",
	"ACPI_BIOS_ERROR",
	"ACPI_BIOS_WARNING",
	"ACPI_DEBUG_PRINT",
	"ACPI_DEBUG_PRINT_RAW",
	"ACPI_ERROR",
	"ACPI_ERROR_METHOD",
	"ACPI_EXCEPTION",
	"ACPI_INFO",
	"acpi_handle_debug",
	"acpi_handle_err",
	"acpi_handle_info",
	"acpi_handle_warn",
	"acpi_os_printf",
	"ACPI_WARNING",
	"ADBG",
	"adc_dbg",
	"adfs_error",
	"adsp_dbg",
	"adsp_err",
	"adv_dbg",
	"adv_err",
	"affs_warning",
	"aha152x_error",
	"airo_print_dbg",
	"airo_print_err",
	"airo_print_info",
	"airo_print_warn",
	"amd64_err",
	"amd64_info",
	"amd64_notice",
	"amd64_warn",
	"apic_debug",
	"apic_printk",
	"apm_error",
	"APRINTK",
	"aq_pr_err",
	"ar5523_dbg",
	"ar5523_err",
	"ar5523_info",
	"arizona_aif_dbg",
	"arizona_aif_err",
	"arizona_aif_warn",
	"arizona_fll_dbg",
	"arizona_fll_err",
	"arizona_fll_warn",
	"arm64_notify_die",
	"arm_notify_die",
	"arc_printk",
	"ASC_DBG",
	"ASC_PRINT",
	"ASD_DPRINTK",
	"asd_printk",
	"asprintf",
	"at76_dbg",
	"ata_dev_dbg",
	"ata_dev_err",
	"ata_dev_info",
	"ata_dev_notice",
	"ata_dev_printk",
	"ata_dev_warn",
	"ata_link_dbg",
	"ata_link_err",
	"ata_link_info",
	"ata_link_notice",
	"ata_link_printk",
	"ata_link_warn",
	"ata_link_warn",
	"ata_port_dbg",
	"ata_port_desc",
	"ata_port_err",
	"ata_port_info",
	"ata_port_notice",
	"ata_port_printk",
	"ata_port_warn",
	"ata_dev_warn",
	"ATH5K_PRINTF",
	"ath10k_dbg",
	"ath10k_err",
	"ath10k_info",
	"ath10k_warn",
	"ATH5K_DBG",
	"ATH5K_DBG_UNLIMIT",
	"ATH5K_ERR",
	"ATH5K_INFO",
	"ATH5K_PRINTF",
	"ATH5K_PRINTK",
	"ATH5K_WARN",
	"ath6kl_dbg",
	"ath6kl_err",
	"ath6kl_info",
	"ath6kl_warn",
	"ath_dbg",
	"ath_err",
	"ath_info",
	"atm_dbg",
	"atm_err",
	"atm_info",
	"atm_printk",
	"atm_rldbg",
	"atm_warn",
	"au0828_isocdbg",
	"audio_debug",
	"audio_error",
	"audio_info",
	"audio_warning",
	"audit_log_config_change",
	"audit_log_link_denied",
	"audit_log_lost",
	"audit_log_rule_change",
	"audit_panic",
	"audit_printk",
	"AUX_DBG",
	"AUX_ERR",
	"AUX_TRACE",
	"b43dbg",
	"b43err",
	"b43info",
	"b43warn",
	"b43legacydbg",
	"b43legacyerr",
	"b43legacyinfo",
	"b43legacywatn",
	"batadv_dbg",
	"batadv_dbg_arp",
	"batadv_err",
	"batadv_info",
	"batadv_warn",
	"bcma_debug",
	"bcma_err",
	"bcma_info",
	"bcma_warn",
	"bdebug",
	"befs_debug",
	"befs_error",
	"bit_dbg",
	"bfq_log",
	"bfq_log_bfqq",
	"binder_debug"
	"binder_user_error",
	"blogic_announce",
	"blogic_err",
	"blogic_info",
	"blogic_notice",
	"blogic_warn",
	"BNX2FC_ELS_DBG",
	"BNX2FC_HBA_DBG",
	"BNX2FC_IO_DBG",
	"BNX2FC_MISC_DBG",
	"BNX2FC_TGT_DBG",
	"BNX2X_DEV_INFO",
	"BNX2X_ERR",
	"BNX2X_ERROR",
	"bootx_printf",
	"brcmf_dbg",
	"brcmf_dbg_info",
	"brcmf_dbg_tx",
	"brcmf_err",
	"brcmf_info",
	"brcmf_helper",
	"brcms_dbg_dma",
	"brcms_dbg_ht",
	"brcms_dbg_info",
	"brcms_dbg_int",
	"brcms_dbg_mac80211",
	"brcms_dbg_rx",
	"brcms_dbg_tx",
	"brcms_err",
	"br_debug",
	"br_err",
	"br_info",
	"br_notice",
	"bsg_dbg",
	"BTC_PRINT",
	"BT_DBG",
	"bt_dev_dbg",
	"bt_dev_err",
	"bt_dev_err_ratelimited",
	"bt_dev_info",
	"bt_dev_warn",
	"BTE_PRINTK",
	"BTE_PRINTKV",
	"BT_ERR",
	"BT_ERR_RATELIMITED",
	"BT_INFO",
	"BT_WARN",
	"btrfs_crit",
	"btrfs_debug",
	"btrfs_err",
	"btrfs_err_rl",
	"btrfs_info",
	"btrfs_warn",
	"BUF_PRINT",
	"buf_printf",
	"BUGFIX",
	"BUGON",
	"BUG_ON",
	"BUGPRINT",
	"BUS_DBG",
	"cache_bug",
	"cafe_dev_dbg",
	"cal_dbg",
	"cal_err",
	"cal_info",
	"cam_dbg",
	"cam_err",
	"cam_warn",
	"cat_printf",
	"ccid2_pr_debug",
	"ccid3_pr_debug",
	"cd_dbg",
	"c_dbg",
	"CDEBUG",
	"c_err",
	"ceph_iod_printf",
	"CERROR",
	"cfq_log",
	"cfq_log_cfqq",
	"ch7006_dbg",
	"ch7006_err",
	"ch7006_info",
	"chan_dbg",
	"chan_err",
	"CH_DBG",
	"CH_ERR",
	"CH_WARN",
	"CHECK",
	"chip_dbg",
	"chip_err",
	"CHSC_LOG",
	"ci_dbg",
	"ci_dbg_print",
	"cifs_dbg",
	"cl_dbg",
	"cl_err",
	"cmm_dbg",
	"cmp_error",
	"CNETERR",
	"cobalt_dbg",
	"cobalt_err",
	"cobalt_info",
	"cobalt_warn",
	"codec_dbg",
	"codec_err",
	"codec_info",
	"codec_warn",
	"color_fprintf",
	"conf_message",
	"conf_printf",
	"conf_warning",
	"con_log",
	"CONN_DBG",
	"CONN_ERR",
	"cont",
	"core_dbg",
	"cow_printf",
	"cpc925_mc_printk",
	"cpc925_printk",
	"cpsw_err",
	"cpsw_info",
	"cpsw_notice",
	"CS_DBGOUT",
	"cs89_dbg",
	"csio_dbg",
	"csio_err",
	"csio_warn",
	"csio_ln_dbg",
	"csio_ln_err",
	"ctcm_pr_debug",
	"CTCM_PR_DEBUG",
	"ctrl_dbg",
	"ctrl_err",
	"ctrl_info",
	"ctrl_warn",
	"ctx_dbg",
	"ctx_err",
	"CWARN",
	"cvmx_dprintf",
	"CX18_ALSA_ERR",
	"CX18_ALSA_WARN",
	"CX18_DEBUG_ALSA_INFO",
	"CX18_DEBUG_API",
	"CX18_DEBUG_FILE",
	"CX18_DEBUG_HI_API",
	"CX18_DEBUG_HI_DMA",
	"CX18_DEBUG_HI_FILE",
	"CX18_DEBUG_HI_IRQ",
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
	"d40_err",
	"d2printk",
	"DAC960_Announce",
	"DAC960_Critical",
	"DAC960_Error",
	"DAC960_Info",
	"DAC960_Notice",
	"DAC960_Progress",
	"DAC960_UserCritical",
	"DAC960_Warning",
	"dax_dbg",
	"dax_err",
	"DB_CFM"
	"DB_CFMN"
	"DB_ECM"
	"DB_ECMN"
	"DB_ESS"
	"DB_ESSN"
	"DBF_DEV_EVENT",
	"DBF_ERROR",
	"DBF_EVENT",
	"DBF_EVENT",
	"DBF_EXCEPTION",
	"dbg",
	"_DBG",
	"DBG",
	"DBG1",
	"DBG2",
	"DBG3",
	"DBG4",
	"DBG_8192C",
	"DBG_8712",
	"DBG_871X",
	"DBG_871X_LEVEL",
	"DBG_88E",
	"DBG_88E_LEVEL",
	"DBGA",
	"DBGA2",
	"DBGBH",
	"DBGC",
	"dbg_bld",
	"dbg_blit",
	"dbg_budg",
	"DBG_BYPASS",
	"DBG_CFG",
	"DBG_CMD",
	"dbg_cmt",
	"DBG_CNT",
	"DBGDCONT",
	"dbg_dentlist",
	"DBG_DEVS",
	"dbg_dump",
	"dbg_eba",
	"DB_GEN",
	"DBGERR",
	"DBG_ERR",
	"dbg_find",
	"dbg_fmt",
	"dbg_fragtree",
	"dbg_fragtree2",
	"dbg_fsbuild",
	"DBGFS_DUMP",
	"DBGFS_DUMP_DI",
	"DBGFS_PRINT_INT",
	"DBGFS_PRINT_STR",
	"DBG_FTL",
	"dbg_gc",
	"dbg_gen",
	"dbg_hid",
	"dbg_info",
	"DBGINFO",
	"DBG_INIT",
	"dbg_inocache",
	"dbg_io",
	"DBG_IRT",
	"DBGISR",
	"dbg_jnl",
	"dbg_jnlk",
	"dbg_log",
	"DBG_LOG",
	"DBG_LOTS",
	"DBG_LOUD",
	"DBG_LOW",
	"dbg_lp",
	"dbg_memalloc",
	"dbg_mnt",
	"dbg_mntk",
	"DBG_MSG",
	"dbg_noderef",
	"DBG_PAT",
	"DBG_PORT",
	"dbgp_ehci_status",
	"dbg_pnp_show_resources",
	"dbgp_printk",
	"DBGPR",
	"dbgprint",
	"DbgPrint",
	"DBG_printk",
	"DBG_PRV1",
	"dbg_qtd",
	"dbg_rcvry",
	"dbg_readinode",
	"dbg_readinode2",
	"dbg_reg",
	"dbg_regs",
	"DBG_REG",
	"DbgRegister",
	"DBG_RES",
	"DBG_RUN",
	"DBG_RUN_SG",
	"DBGS",
	"dbg_scan",
	"dbg_summary",
	"dbg_td",
	"dbg_tnc",
	"dbg_tnck",
	"DBG_TRC",
	"dbg_verbose",
	"DBG_VERBOSE",
	"dbg_wl",
	"dbg_xattr",
	"DBMSG",
	"DBP_SAVE",
	"DB_PCM",
	"DB_RMT",
	"DB_RMTN",
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
	"DC_ERR",
	"DC_ERROR",
	"dcprintk",
	"dctlprintk",
	"DDB",
	"dd_dev_dbg",
	"dd_dev_err",
	"dd_dev_info",
	"dd_dev_info_ratelimited",
	"dd_dev_warn",
	"ddlprintk",
	"ddprintk",
	"ddprintk_cont",
	"deb",
	"DEB",
	"DEB1",
	"DEB2",
	"DEB3",
	"DEB_CAP",
	"deb_chk",
	"DEB_D",
	"DEBC_printk",
	"deb_data",
	"deb_decode",
	"DEB_EE",
	"deb_eeprom",
	"deb_err",
	"deb_fe",
	"deb_fw",
	"deb_fwdata",
	"deb_fw_load",
	"DEBG",
	"DEB_G",
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
	"deb_srch",
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
	"DEBUG_bytes",
	"debug_cclk_get",
	"DEBUG_DBG",
	"debug_dcl",
	"DEBUG_ERR",
	"_debug_bug_printk",
	"DEBUG_INFO",
	"DEBUG_IRQ",
	"debugl1",
	"debug_log",
	"DEBUG_LOG",
	"DEBUG_MARKER",
	"debug_msg",
	"DEBUG_MSG",
	"debug_name",
	"DEBUGOUTBUF",
	"DEBUGP",
	"debug_pci",
	"debug_polling",
	"DEBUG_print",
	"debug_printf",
	"debug_print_fifo_channel_state",
	"debug_print_if_state",
	"debug_print_isp_state",
	"debug_print_object",
	"debug_print_rmap",
	"debug_print_sp_state",
	"debug_putstr",
	"DEBUGREAD",
	"DEBUG_REQ",
	"debug_shrink_set",
	"debug_sprintf_event",
	"debug_sprintf_exception",
	"DEBUGTRDMA",
	"DEBUGTXINT",
	"debug_timestamp",
	"DEBUGTXINT",
	"DEBUG_VAE",
	"DEBUG_WARN",
	"DEBUGWRITE",
	"deb_uxfer",
	"deb_v8",
	"DEB_VBI",
	"deb_xfer",
	"decrypt_done",
	"decrypt_fail",
	"decrypt_interrupt",
	"D_EEPROM",
	"DERROR",
	"dev",
	"dev_alert",
	"dev_alert_once",
	"dev_alert_ratelimited",
	"dev_crit",
	"dev_crit_once",
	"dev_crit_ratelimited",
	"dev_dbg",
	"dev_dbgdma",
	"deb_dbg_f",
	"deb_dbg_lvl",
	"deb_dbg_ratelimited",
	"deb_dbg_stamp",
	"dev_dbg_once",
	"dev_emerg",
	"dev_emerg_once",
	"dev_emerg_ratelimited",
	"dev_err",
	"dev_err_console",
	"dev_err_once",
	"dev_err_ratelimited",
	"dev_info",
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
	"devtprintk",
	"devtverboseprintk",
	"dev_vdbg",
	"dev_warn",
	"dev_WARN",
	"dev_warn_once",
	"dev_WARN_ONCE",
	"dev_warn_ratelimited",
	"dewtprintk",
	"dexitprintk",
	"dfailprintk",
	"dfprintk",
	"dhsprintk",
	"df_trace",
	"die",
	"dio_on",
	"__die_if_kernel",
	"die_if_kernel",
	"die_if_no_fixup",
	"die_nmi",
	"dintprintk",
	"dioprintk",
	"D_INFO",
	"DIPRINTK",
	"D_ISR",
	"diva_log_info",
	"D_LED",
	"dlog",
	"dlprintk",
	"dm9000_dbg",
	"DMCRIT",
	"DMDEBUG",
	"DMDEBUG_LIMIT",
	"DMEMIT",
	"DMERR",
	"DMERR_LIMIT",
	"DMESG",
	"DMESGE",
	"dmfprintk",
	"DMINFO",
	"DMSG",
	"DMWARN",
	"DMWARN_LIMIT",
	"dmz_dev_debug",
	"dmz_dev_err",
	"dn_serial_print",
	"do_BUG",
	"doc_dbg",
	"doc_err",
	"doc_info",
	"doc_vdbg",
	"do_error",
	"do_trap",
	"do_warning",
	"do_warning_event",
	"dout",
	"DP",
	"DP_CONT",
	"DPC",
	"DPD",
	"DPD1",
	"DP_DEBUG",
	"DP_ERR",
	"DP_INFO",
	"DP_VERBOSE",
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
	"dprintk1",
	"dprintk2",
	"dprintkdbg",
	"dprintk_cont",
	"dprintk_i2c",
	"dprintkl",
	"dprintk_mmu",
	"dprintk_pte",
	"dprintk_rcu",
	"dprintk_sect_loss",
	"dprintk_sr",
	"dprintk_tscheck",
	"DPRINT_ovfl",
	"DPRINT_TLA",
	"DPS",
	"DPS1",
	"DPX",
	"DPX1",
	"D_QOS",
	"D_RADIO",
	"D_RATE",
	"D_RF_KILL",
	"drbd_alert",
	"drbd_dbg",
	"drbd_emerg",
	"drbd_err",
	"drbd_info",
	"drbd_warn",
	"dreplyprintk",
	"DRM_DEBUG",
	"DRM_DEBUG_ATOMIC",
	"DRM_DEBUG_DRIVER",
	"DRM_DEBUG_KMS",
	"DRM_DEBUG_KMS_RATELIMITED",
	"DRM_DEBUG_LEASE",
	"DRM_DEBUG_PRIME",
	"DRM_DEBUG_VBL",
	"DRM_DEV_DEBUG_KMS",
	"DRM_DEV_ERROR",
	"DRM_ERROR",
	"DRM_ERROR_RATELIMITED",
	"DRM_INFO",
	"DRM_INFO_ONCE",
	"DRM_NODE",
	"DRM_NOTE",
	"DRM_WARN",
	"drm_rect_debug_print",
	"drm_printf",
	"drm_printf_indent",
	"dsb",
	"dsasprintk",
	"dsawideprintk",
	"dsgprintk",
	"dsprintk",
	"D_SCAN",
	"DSSDBG",
	"DSSERR",
	"DSSWARN",
	"D_STATS",
	"D_TEMP",
	"DTN_INFO",
	"dtmprink",
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
	"dynamic_hex_dump",
	"E",
	"e752x_printk",
	"e7xxx_printk",
	"ea_bdebug",
	"ea_idebug",
	"earlier",
	"early_panic",
	"early_pgtable_allocfail",
	"early_platform_driver_probe",
	"early_platform_driver_register_all",
	"early_print",
	"early_printk",
	"ec_dbg_drv",
	"ec_dbg_evt",
	"ec_dbg_raw",
	"ec_dbg_req",
	"ec_dbg_stm",
	"ec_log_drv",
	"ecryptfs_printk",
	"edac_dbg",
	"edac_mc_handle_error",
	"edac_mc_printk",
	"edac_printk",
	"e_dbg",
	"e_dev_err",
	"e_dev_info",
	"e_dev_warn",
	"e_err",
	"EE",
	"efi_printk",
	"efm32_spi_vdbg",
	"efm_debug",
	"ehci_dbg",
	"ehci_err",
	"ehci_info",
	"ehci_node",
	"ehci_off",
	"ehci_warn",
	"ehci_dump",
	"e_info",
	"EISA_DBG",
	"elantech_debug",
	"em28xx_isocdbg",
	"em28xx_regdbg",
	"em28xx_videodbg",
	"en_dbg",
	"en_err",
	"en_info",
	"en_warn",
	"ep_dbg",
	"ep_err",
	"ep_info",
	"ep_vdbg",
	"ep_warn",
	"EP_INFO",
	"eprintf",
	"eprintk",
	"ep_warn"
	"err",
	"ERR",
	"err_chk",
	"err_cpu",
	"err_msg",
	"ERR_MSG",
	"error",
	"ERROR",
	"ErrorF",
	"error_putstr",
	"error_with_pos",
	"err_printf",
	"err_printk",
	"err_puts",
	"err_str",
	"err_src",
	"errx"
	"esas2r_debug",
	"esas2r_hdebug",
	"esas2r_trace",
	"esas2r_log",
	"esas2r_log_dev",
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
	"esw_debug",
	"esw_info",
	"esw_warn",
	"EVENT",
	"e_warn",
	"EXCEPTION",
	"EXOFS_DBGMSG",
	"EXOFS_DBGMSG2",
	"EXOFS_ERR",
	"ext2_debug",
	"ext2_error",
	"exy2_msg",
	"ext4_abort",
	"ext4_debug",
	"ext4_error",
	"ext4_lo_info",
	"ext4_msg",
	"ext4_warning",
	"ext4_warning_inode",
	"EXT4_ERROR_INODE",
	"ext_debug",
	"f2fs_cp_error",
	"f2fs_msg",
	"fail",
	"fail_reason",
	"FAIL",
	"fatal",
	"fatal_perror",
	"fas216_log",
	"fas216_log_target",
	"fatal_perror",
	"fat_fs_error",
	"fat_msg",
	"fb_dbg",
	"fb_err",
	"fb_info",
	"fb_notice",
	"fb_warn",
	"fbtft_init_dbg",
	"fbtft_par_dbg",
	"fb_warn",
	"FC_DISC_DBG",
	"FC_EXCH_DBG",
	"FC_RPORT_DBG",
	"FC_SCSI_DBG",
	"FC_FCP_DBG",
	"FC_LPORT_DBG",
	"FCOE_DBG",
	"FCOE_NETDEV_DBG",
	"FC_RPORT_ID_DBG",
	"FCS_ONLINE",
	"f_dddprintk",
	"f_ddprintk",
	"f_dprintk",
	"fhci_dbg",
	"fhci_err",
	"fhci_info",
	"fhci_vdbg",
	"FIPS_DBG",
	"FIPS_LOG",
	"fit_dbg",
	"fit_dbg_verbose",
	"fit_pr",
	"flow_dump",
	"flow_log",
	"fmdbg",
	"fmerr",
	"fmwarn",
	"fotg210_dbg",
	"fotg210_err",
	"fotg210_info",
	"fprintf",
	"fputs",
	"F_printk",
	"fs_dprintk",
	"fs_err",
	"fs_info",
	"fs_warn",
	"fsl_mc_printk",
	"fusb302_log",
	"FW_BUG",
	"fw_err",
	"fw_notice",
	"fwtty_dbg",
	"fwtty_err",
	"fwtty_err_ratelimited",
	"fwtty_notice",
	"gcam_dbg",
	"gcam_err",
	"gdbstub_printk",
	"gfs2_print_dbg",
	"gig_dbg",
	"gossip_debug",
	"gossip_err",
	"gpio_mockup_err",
	"gpiod_dbg",
	"gdbstub_printk",
	"gr_dbgprint_request",
	"gru_abort",
	"gru_dng",
	"gspca_dbg",
	"gspca_err",
	"g_error",
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
	"gvt_vgpu_err",
	"hdmi_log",
	"HEAD_DBG",
	"hfi1_cdbg",
	"hfi1_dbg_early",
	"hfi1_early_err",
	"hfi1_early_info",
	"hfs_dbg",
	"hfs_dbg_cont",
	"hprintk",
	"HPRINTK",
	"hid_dbg",
	"hid_debug_event",
	"hid_err",
	"hid_info",
	"hid_warn",
	"host1x_debug_output",
	"hpfs_error",
	"HPI_DEBUG_LOG",
	"hprintk",
	"HPRINTK",
	"hpsa_show_dev_msg",
	"hso_dbg",
	"ht_dbg",
	"ht_dbg_ratelimited",
	"hwc_debug",
	"hw_dbg",
	"hw_err",
	"hwc_debug",
	"hw_dbg",
	"i2c_cont",
	"i2c_dbg",
	"i2c_dprintk",
	"i2c_hid_dbg",
	"i40e_debug",
	"i40iw_debug",
	"i40iw_pr_err",
	"i40iw_pr_info",
	"i40iw_pr_warn",
	"i5000_printk",
	"i5400_printk",
	"i7300_mc_printk",
	"i7core_printk",
	"i82875p_printk",
	"i82975x_printk",
	"i915_error_printf",
	"I915_STATE_WARN",
	"IA64_MCA_DEBUG",
	"I915_STATE_WARN",
	"IA_CSS_LOG",
	"ia_css_print",
	"IA_CSS_WARNING",
	"IA64_MCA_DEBUG",
	"ibmvfc_dbg",
	"ibmvfc_log",
	"ibss_dbg"
	"icmp_error_log",
	"icmpv6_error_log",
	"ics_panic",
	"ide_debug_log",
	"ie31200_printk",
	"IEEE80211_DEBUG",
	"IEEE80211_DEBUG_DROP",
	"IEEE80211_DEBUG_EAP",
	"IEEE80211_DEBUG_FRAG",
	"IEEE80211_DEBUG_MGMT",
	"IEEE80211_DEBUG_QOS",
	"IEEE80211_DEBUG_SCAN",
	"IEEE80211_DEBUG_WX",
	"IEEE80211_ERROR",
	"IEEE80211_INFO",
	"ieee802154_print_addr",
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
	"IL_WARN_ONCE",
	"ima_log_string",
	"imm_fail",
	"INF_MSG",
	"info",
	"INFO",
	"inform",
	"input_dbg",
	"intc_irqpin_dbg",
	"intel_pt_log",
	"intel_pt_log_at",
	"intel_pt_log_to",
	"intel_pt_print_info_str",
	"INTERNAL_DEBMSG",
	"INTERNAL_ERRMSG",
	"INTERNAL_INFMSG",
	"INTERNAL_WRNMSG"
	"INTPRINTK",
	"ioapic_debug",
	"iop_pr_cont",
	"iop_pr_debug",
	"IOR_DBG",
	"ipoib_dbg",
	"ipr_dbg",
	"ipr_err",
	"ipr_hcam_err",
	"ipr_info",
	"IPRINTK",
	"ipr_phys_res_err",
	"ipr_res_err",
	"ipr_trace",
	"ipoib_dbg",
	"ipoib_dbg_mcast",
	"ipoib_warn",
	"IPS_PRINTK",
	"IP_VS_DBG",
	"IP_VS_DBG_RL",
	"IP_VS_ERR_RL",
	"ip_vs_scheduler_err",
	"IPW_DEBUG",
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
	"ir_dbg",
	"ir_dprintk",
	"IR_dprintk",
	"irqc_dbg",
	"irq_dbg",
	"irq_err",
	"iscsi_conn_printk",
	"ISCSI_DBG_CONN",
	"ISCSI_DBG_EH",
	"ISCSI_DBG_SESSION",
	"ISCSI_DBG_TCP",
	"ISCSI_DBG_TRANS_CONN",
	"ISCSI_DBG_TRANS_SESSION",
	"ISCSI_SW_TCP_DBG",
	"iser_dbg",
	"iser_err",
	"iser_info",
	"iser_warn",
	"isert_dbg",
	"isert_err",
	"isert_info",
	"isert_print_wc",
	"isert_warn",
	"isp_dbg",
	"itd_dbg",
	"itd_dbg_verbose",
	"itd_info",
	"itd_warn",
	"ite_dbg",
	"ite_dbg_verbose",
	"ite_pr",
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
	"IWL_DEBUG_11H",
	"IWL_DEBUG_ASSOC",
	"IWL_DEBUG_CALIB",
	"IWL_DEBUG_COEX",
	"IWL_DEBUG_DEV",
	"IWL_DEBUG_DEV_RADIO",
	"IWL_DEBUG_DROP",
	"IWL_DEBUG_EEPROM",
	"IWL_DEBUG_FW",
	"IWL_DEBUG_HC",
	"IWL_DEBUG_HT",
	"IWL_DEBUG_INFO",
	"IWL_DEBUG_ISR",
	"IWL_DEBUG_LAR",
	"IWL_DEBUG_MAC80211",
	"IWL_DEBUG_POWER",
	"IWL_DEBUG_QUIET_RFKILL",
	"IWL_DEBUG_QUOTA",
	"IWL_DEBUG_RADIO",
	"IWL_DEBUG_RATE",
	"IWL_DEBUG_RATE_LIMIT",
	"IWL_DEBUG_RF_KILL",
	"IWL_DEBUG_RPM",
	"IWL_DEBUG_RX",
	"IWL_DEBUG_SCAN",
	"IWL_DEBUG_STATS",
	"IWL_DEBUG_STATS_LIMIT",
	"IWL_DEBUG_TDLS",
	"IWL_DEBUG_TE",
	"IWL_DEBUG_TEMP",
	"IWL_DEBUG_TX",
	"IWL_DEBUG_TX_QUEUES",
	"IWL_DEBUG_TX_REPLY",
	"IWL_DEBUG_WEP",
	"IWL_ERR",
	"IWL_ERR_DEV",
	"IWL_INFO",
	"IWL_WARN",
	"IX25DEBUG",
	"jbd_debug",
	"jent_panic",
	"jffs2_dbg"
	"JFFS2_DEBUG",
	"JFFS2_ERROR",
	"JFFS2_NOTICE",
	"JFFS2_WARNING",
	"jfs_err",
	"jfs_error",
	"jfs_info",
	"jfs_warn",
	"jsm_dbg",
	"K1212_DEBUG_PRINTK",
	"K1212_DEBUG_PRINTK_VERBOSE",
	"kasprintf",
	"kdb_printf",
	"kdcore",
	"kdebug",
	"KINFO",
	"kmemleak_stop",
	"kmemleak_warn",
	"kputs",
	"kvasprintf",
	"kvm_debug",
	"kvm_debug_ratelimited",
	"kvm_err",
	"KVM_EVENT",
	"kvm_info",
	"kvm_pr_debug_ratelimited",
	"kvm_pr_err_ratelimited",
	"kvm_pr_unimpl",
	"l2m_debug",
	"l2tp_dbg",
	"l2tp_info",
	"l3_debug",
	"lapb_dbg",
	"LCONSOLE_ERROR",
	"LCONSOLE_ERROR_MSG",
	"LCONSOLE_INFO",
	"LCONSOLE_WARN",
	"LDBG",
	"ldcdbg",
	"LDLM_DEBUG",
	"LDLM_DEBUG_NOLOCK",
	"LDLM_ERROR",
	"ldm_crit",
	"ldm_debug",
	"ldm_error",
	"ldm_info",
	"led_print",
	"lg_dbg",
	"lg_debug",
	"lg_err",
	"lg_reg",
	"lg_warn",
	"libcfs_debug_msg",
	"LIBFCOE_TRANSPORT_DBG",
	"LIBFCOE_FIP_DBG",
	"LIBFCOE_SYSFS_DBG",
	"LIBIPW_DEBUG_DROP",
	"LIBIPW_DEBUG_FRAG",
	"LIBIPW_DEBUG_INFO",
	"LIBIPW_DEBUG_MGMT",
	"LIBIPW_DEBUG_QOS",
	"LIBIPW_DEBUG_SCAN",
	"LIBIPW_DEBUG_WX",
	"LIBIPW_ERROR",
	"link_debug",
	"link_print",
	"log",
	"LOG",
	"LOG_BLOB",
	"LOG_DBG",
	"log_debug",
	"log_bug",
	"log_err",
	"LOG_ERROR",
	"log_error",
	"LOG_INFO",
	"log_info",
	"LOG_PARSE",
	"log_print",
	"LOG_WARN",
	"log_warn",
	"mb_debug",
	"mce_panic",
	"mcg_debug_group",
	"mcg_warn",
	"mcg_warn_group",
	"mc_printk",
	"mcsa_dbg",
	"mei_err",
	"mei_msg",
	"merror",
	"message",
	"memblock_dbg",
	"merror",
	"METHOD_TRACE",
	"mfc_debug",
	"mfc_err",
	"mfc_err_limited",
	"mfd_fail_new",
	"mhwmp_dbg",
	"MG_DBG",
	"mips_display_message",
	"mmiotrace_printk",
	"mlme_dbg",
	"mlog",
	"mlog_bug_on_msg",
	"mlx4_dbg",
	"mlx4_err",
	"mlx4_ib_warn",
	"mlx4_info",
	"mlx4_warn",
	"mlx5_core_dbg",
	"mlx5_core_err",
	"mlx5_core_info",
	"mlx5_core_warn",
	"mlx5_fpga_dbg",
	"mlx5_fpga_err",
	"mlx5_fpga_info",
	"mlx5_fpga_warn",
	"mlx5_fpga_warn_ratelimited",
	"mlx5_ib_dbg",
	"mlx5_ib_err",
	"mlx5_ib_warn",
	"mmiotrace_printk",
	"mpath_dbg",
	"mpath_dbg",
	"mprintk",
	"mps_dbg",
	"mod_debug",
	"mod_err",
	"mpath_dbg",
	"mpl_dbg",
	"mprintk",
	"mpsslog",
	"msg",
	"MSG",
	"MSG_8192C",
	"MSG_88E",
	"msync_dbg",
	"mthca_dbg",
	"mthca_err",
	"mthca_warn",
	"mtk_mdp_dbg",
	"mtk_mdp_err",
	"mtk_v4l2_debug",
	"mtk_v4l2_err",
	"mtk_vcodec_debug",
	"mtk_vcodec_err",
	"MTS_DEBUG",
	"MTS_ERROR",
	"mus_dbg",
	"mv_dprintk",
	"mv_printk",
	"mwifiex_dbg",
	"mxl_dbg",
	"mxl_debug",
	"mxl_debug_adv",
	"mxl_i2c",
	"mxl_i2c_adv",
	"mxl_info",
	"mxl_warn",
	"mxm_dbg",
	"mxm_err,"
	"ncp_dbg",
	"ncp_vdbg",
	"ND_PRINK"
	"neigh_dbg",
	"nes_debug",
	"NDD_TRACE",
	"net_crit_ratelimited",
	"net_dbg_ratelimited",
	"netdev_alert",
	"netdev_crit",
	"netdev_dbg",
	"netdev_emerg",
	"netdev_err",
	"netdev_info",
	"netdev_notice",
	"NETDEV_PR_FMT",
	"netdev_printk",
	"netdev_vdbg",
	"netdev_warn",
	"netdev_WARN",
	"net_err_ratelimited",
	"netif_crit",
	"netif_dbg",
	"netif_err",
	"netif_info",
	"netif_notice",
	"netif_printk",
	"netif_vdbg",
	"netif_warn",
	"net_info_ratelimited",
	"net_notice_ratelimited",
	"net_warn_ratelimited",
	"nfc_err",
	"nfc_info",
	"NFCSIM_DBG",
	"NFCSIM_ERR",
	"NFDEBUG",
	"nfp_err",
	"nfp_info",
	"nfp_warn",
	"nilfs_error",
	"nilfs_msg",
	"nmi_debug",
	"nmi_panic",
	"nn_dbg",
	"nn_dp_warn",
	"nn_err",
	"nn_info",
	"nn_warn",
	"noisy_printk",
	"non_fatal",
	"no_printk",
	"NPRINTK",
	"np_err",
	"np_info",
	"np_notice",
	"NS_DBG",
	"NS_ERR",
	"NS_INFO",
	"NS_LOG",
	"NS_WARN",
	"nsp32_dbg",
	"nsp32_msg",
	"nsp_dbg",
	"nsp_msg",
	"ntfs_debug",
	"ntfs_error",
	"ntfs_warning",
	"numadbg",
	"nvdev_error",
	"nvdev_info",
	"nvdev_trace",
	"NV_ERROR",
	"NV_WARN",
	"nvif_debug",
	"nvif_error",
	"nvif_fatal",
	"nvif_ioctl",
	"nvif_trace",
	"nvkm_debug",
	"nvkm_error",
	"nvkm_fatal",
	"nvkm_info",
	"nvkm_printk",
	"nvkm_trace",
	"nvkm_warn",
	"nvt_dbg",
	"nvt_dbg_verbose",
	"ocb_dbg",
	"ocfs2_error",
	"ocfs2_log_dlm_error",
	"ohci_dbg",
	"ohci_dbg_sw",
	"ohci_err",
	"ohci_notice",
	"ohci_warn",
	"OPRINTK",
	"ORE_DBGMSG",
	"ORE_DBGMSG2",
	"ORE_ERR",
	"OSC_IO_DEBUG",
	"OSD_DEBUG",
	"OSD_ERR",
	"OSDBLK_DEBUG",
	"OSD_DEBUG",
	"OSD_ERR",
	"OSD_INFO",
	"OSD_SENSE_PRINT1",
	"OSD_SENSE_PRINT2",
	"OUTP_DBG",
	"OUTP_ERR",
	"oxu_dbg",
	"oxu_err",
	"oxu_info",
	"oxu_vdbg",
	"p9_debug",
	"packet_log",
	"pair_err",
	"pair_dbg",
	"pair_err",
	"panic",
	"PANIC",
	"parse_err",
	"pch_dbg",
	"pch_err",
	"pch_pci_dbg",
	"pch_pci_err",
	"__pcidebug",
	"pci_dbg",
	"pci_err",
	"pci_info",
	"pci_note_irq_problem",
	"pci_notice",
	"pci_printk",
	"pci_warn",
	"pcm_dbg",
	"pcm_err",
	"pcr_dbg",
	"PDBG",
	"PDEBUG",
	"pdprintf",
	"PDPRINTK",
	"pdtlb_kernel",
	"pe_err",
	"pe_info",
	"pe_warn",
	"PERR",
	"perror",
	"PERROR",
	"pgd_ERROR",
	"pgprintk",
	"phydev_dbg",
	"phydev_err",
	"phx_mmu",
	"phx_warn",
	"PHYDM_SNPRINTF",
	"PHY_ERR",
	"p_info",
	"pid_dbg_print",
	"pio_rx_error",
	"PINFO",
	"pk_error",
	"pkt_dbg",
	"pkt_err",
	"pkt_info",
	"pkt_notice",
	"PKT_ERROR",
	"PM8001_DISC_DBG",
	"PM8001_EH_DBG",
	"PM8001_FAIL_DBG",
	"PM8001_IO_DBG",
	"PM8001_MSG_DBG",
	"pm8001_printk",
	"pmcraid_err",
	"pmcraid_info",
	"pm_dev_dbg",
	"pm_pr_dbg",
	"pmd_ERROR",
	"pmz_debug",
	"pmz_error",
	"pmz_info",
	"pnd2_mc_printk",
	"pnd2_printk",
	"pnp_dbg",
	"pnp_printf",
	"pnpbios_print_status",
	"ppa_fail",
	"ppc4xx_edac_mc_printk",
	"ppc4xx_edac_printk",
	"PP_DBG_LOG",
	"pr",
	"PR",
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
	"pr_devel_once",
	"pr_devel_ratelimited",
	"pr_devinit",
	"PR_DEVEL",
	"pr_efi",
	"pr_efi_err",
	"pr_emerg",
	"pr_emerg_once",
	"pr_emerg_ratelimited",
	"pr_err",
	"pr_err_once",
	"pr_err_ratelimited",
	"pr_err_with_code",
	"pr_fmt",
	"pr_hard",
	"pr_hardcont",
	"pr_info",
	"pr_info_ipaddr",
	"pr_info_once",
	"pr_info_ratelimited",
	"pr_init",
	"print",
	"PRINT",
	"PRINT_ADDR",
	"PRINT_ATTR",
	"PRINT_CCK_RATE",
	"PRINT_CLOCK",
	"PRINT_CMD",
	"print_credit_info",
	"printd",
	"PRINTD",
	"PRINTDB",
	"print_dpcm_info",
	"print_dbg",
	"PRINT_DEBUG",
	"print_err",
	"PRINT_ERR",
	"PRINT_FCALL_ERROR",
	"printf",
	"PRINTF",
	"printf_alert",
	"PRINT_FATAL",
	"PRINT_FIELD",
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
	"PRINTK_2",
	"PRINTK3",
	"PRINTK_5",
	"printk_deferred",
	"printk_deferred_once",
	"printk_emit",
	"PRINTK_ERROR",
	"PRINTKE",
	"PRINTKI",
	"printk_once",
	"printk_ratelimited",
	"print_lockdep_off",
	"PRINT_MASKED_VAL",
	"PRINT_MASKED_VAL_L2",
	"PRINT_MASKED_VAL_MISC",
	"PRINT_MASKED_VALP",
	"printl",
	"print_message",
	"print_metric",
	"print_symbol",
	"print_temp",
	"print_testname",
	"print_track",
	"print_warn",
	"PRINT_WARN",
	"PRINTR",
	"printv",
	"pr_notice",
	"pr_notice_once",
	"pr_notice_ratelimited",
	"PROBE_DEBUG",
	"prom_debug",
	"prom_panic",
	"prom_print",
	"prom_printf",
	"prom_reboot",
	"prom_stdout",
	"prom_warn",
	"prop_warn",
	"pr_probe",
	"pr_stat",
	"pr_trace",
	"pr_vdebug",
	"pr_vlog",
	"pr_warn",
	"pr_warning",
	"pr_warning_once",
	"pr_warn_once",
	"pr_warn_ratelimited",
	"prx",
	"ps_dbg",
	"psmouse_dbg",
	"psmouse_err",
	"psmouse_info",
	"psmouse_printk",
	"psmouse_warn",
	"puts",
	"puts_raw",
	"putstr",
	"PWARN",
	"PWC_DEBUG_FLOW",
	"PWC_DEBUG_IOCTL",
	"PWC_DEBUG_MEMORY",
	"PWC_DEBUG_OPEN",
	"PWC_DEBUG_PROBE",
	"PWC_DEBUG_SIZE",
	"PWC_ERROR",
	"PWC_INFO",
	"PWC_TRACE",
	"PWC_WARNING",
	"Py_FatalError",
	"qdisc_warn_nonwc",
	"QDUMP",
	"QERROR",
	"QEDF_ERR",
	"QEDF_INFO",
	"QEDF_WARN",
	"QEDI_ERR",
	"QEDI_INFO",
	"QEDI_NOTICE",
	"QEDI_WARN",
	"qib_dev_err",
	"qib_devinfo",
	"qib_dev_porterr",
	"ql4_printk",
	"ql_dbg",
	"ql_log",
	"quota_error",
	"qxl_io_log",
	"raid10_log",
	"raid1_log",
	"rbd_warn",
	"RBRQ_HBUF_ERR",
	"RCU_LOCKDEP_WARN",
	"rdev_dbg",
	"rdev_err",
	"rdev_info",
	"rdev_warn",
	"rds_ib_conn_error",
	"rdrif_dbg",
	"rdrif_err",
	"rdsdebug",
	"RDBG",
	"r128_print_dirty",
	"r_ddprintk",
	"r_dprintk",
	"regs__printf",
	"rdsdebug",
	"REFCOUNT_WARN",
	"reiserfs_abort",
	"reiserfs_error",
	"reiserfs_info",
	"reiserfs_panic",
	"reiserfs_printk",
	"reiserfs_warning",
	"report",
	"RGMII_DBG",
	"RGMII_DBG2",
	"riocm_debug",
	"riocm_error",
	"riocm_warn",
	"rl_printf",
	"rmap_printk",
	"rmcd_debug",
	"rmcd_error",
	"rmcd_warn",
	"rmi_dbg",
	"RPRINTK",
	"RTL_DEBUG",
	"RT_TRACE",
	"rt2x00_dbg",
	"rt2x00_eeprom_dbg",
	"rt2x00_err",
	"rt2x00_info",
	"rt2x00_probe_err",
	"rt2x00_warn",
	"RTL_DEBUG",
	"RPRINT",
	"RWDEBUG",
	"rvt_pr_err",
	"rvt_pr_info",
	"RXD",
	"RXPRINTK",
	"RXS_ERR",
	"s3c_freq_dbg",
	"s3c_freq_iodbg",
	"rmcd_error",
	"rmcd_warn",
	"RPRINTK",
	"RTL_DEBUG",
	"RT_TRACE",
	"RWDEBUG",
	"RXD",
	"RXPRINTK",
	"RXS_ERR",
	"s2255_dev_err",
	"s3c_freq_dbg",
	"s3c_freq_iodbg",
	"S3C_PMDBG",
	"SAS_DPRINTK",
	"sas_ata_printk",
	"sas_printk",
	"sbridge_mc_printk",
	"sbridge_printk",
	"sclp_early_printk",
	"scrub_print_warning",
	"sched_numa_warn",
	"scif_err_debug",
	"sclp_early_printk",
	"scmd_printk",
	"SCM_LOG",
	"scnprintf",
	"__sdata_dbg",
	"__sdata_err",
	"sdata_err",
	"__sdata_info",
	"sdata_info",
	"SDEBUG",
	"sdev_printk",
	"sd_first_printk",
	"SDMA_DBG",
	"sd_printk",
	"se_kernmode_warn",
	"semantic_error",
	"SEQ_OPTS_PRINT",
	"SEQ_OPTS_PUTS",
	"seq_buf_printf",
	"seq_printf",
	"seq_puts",
	"SEQ_printf",
	"setup_early_printk",
	"shost_printk",
	"sil164_dbg",
	"sil164_err",
	"sil164_info",
	"skx_mc_printk",
	"skx_printk",
	"slab_bug",
	"slab_err",
	"slab_error",
	"slab_fix",
	"slice_dbg",
	"sm_printk",
	"SMP_DBG",
	"smp_debug",
	"sm_printk",
	"SMSC_TRACE",
	"SMSC_WARN",
	"SMT_PANIC",
	"snd_iprintf",
	"snd_printd",
	"snd_printdd",
	"snd_printddd",
	"snd_printk",
	"SNIC_DBG",
	"SNIC_DISC_DBG",
	"SNIC_ERR",
	"SNIC_HOST_ERR",
	"SNIC_HOST_INFO",
	"SNIC_INFO",
	"SNIC_SCSI_DBG",
	"snprintf",
	"sprintf",
	"SOCK_DEBUG",
	"sock_warn_obsolete_bsdism",
	"sprintf",
	"sprinthx",
	"sprinthx4",
	"srm_printk",
	"sr_printk",
	"ssb_cont",
	"ssb_dbg",
	"ssb_emerg",
	"ssb_err",
	"ssb_info",
	"ssb_notice",
	"ssb_warn",
	"SSI_LOG",
	"SSI_LOG_DEBUG",
	"SSI_LOG_ERR",
	"SSI_LOG_INFO",
	"ssp_dbg",
	"sta_dbg",
	"starget_printk",
	"stk1160_dbg",
	"stk1160_err",
	"stk1160_info",
	"stk1160_warn",
	"STK_ERROR",
	"STK_INFO",
	"st_printk",
	"str_printf",
	"svc_printk",
	"SWARN",
	"swim3_dbg",
	"swim3_err",
	"swim3_info",
	"swim3_warn",
	"synth_printf",
	"tb_ctl_info",
	"tb_ctl_warn",
	"tb_ctl_WARN",
	"tb_err",
	"tb_info",
	"tb_port_info",
	"tb_port_warn",
	"tb_port_WARN",
	"tb_sw_info",
	"tb_sw_info",
	"tb_sw_warn",
	"tb_sw_WARN",
	"tb_tunnel_info",
	"tb_tunnel_warn",
	"tb_tunnel_WARN",
	"tb_warn",
	"tb_WARN",
	"tcp_error_log",
	"tcpm_log",
	"tda_cal",
	"tda_dbg",
	"tda_err",
	"tda_info",
	"tda_map",
	"tda_reg",
	"tda_warn",
	"tdls_dbg",
	"tgt_dbg",
	"tgt_err",
	"tgt_info",
	"tgt_log",
	"tipc_tlv_sprintf",
	"TLAN_DBG",
	"tm6000_err",
	"tmon_log",
	"TM_DEBUG",
	"tomoyo_io_printf",
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
	"trace_regcache_sync",
	"trace_rvt_dbg",
	"trace_seq_printf",
	"trace_seq_puts",
	"trace_snd_soc_jack_irq",
	"ts_debug",
	"tsi_debug",
	"tsi_err",
	"tsi_info",
	"TTM_DEBUG",
	"tty_debug",
	"tty_debug_hangup",
	"tty_debug_wait_until_sent",
	"tty_err",
	"tty_info_ratelimited",
	"tty_ldisc_debug",
	"tty_notice",
	"tty_warn",
	"tty_write_message",
	"tuner_dbg",
	"tuner_err",
	"tuner_info",
	"tuner_warn",
	"TWDEBUG",
	"TW_PRINTK",
	"tx_dbg",
	"TXPRINTK",
	"ubi_err",
	"ubifs_err",
	"ubifs_errc",
	"ubifs_msg",
	"ubifs_warn",
	"ubi_msg",
	"ubi_warn",
	"udbg_printf",
	"udbg_puts",
	"udbg_write",
	"udf_debug",
	"udf_err",
	"udf_info",
	"udf_warn",
	"udp_error_log",
	"udplite_error_log",
	"uea_dbg",
	"uea_err",
	"uea_info",
	"uea_vdbg",
	"uea_warn",
	"ufs_error",
	"ufs_panic",
	"ufs_warning",
	"ugeth_vdbg",
	"ultra_iprintf",
	"unaligned_panic",
	"unaligned_printk",
	"unpoison_pr_info",
	"unw_debug",
	"uprobe_warn",
	"urb_dbg",
	"URB_DBG",
	"URB_DPRINT",
	"usb_audio_dbg",
	"usb_audio_err",
	"usb_audio_info",
	"usb_dbg",
	"usb_err",
	"usb_info",
	"usb_warn",
	"usbip_dbg_eh",
	"usbip_dbg_stub_rx",
	"usbip_dbg_stub_tx",
	"usbip_dbg_vhci_hc",
	"usbip_dbg_vhci_rh",
	"usbip_dbg_vhci_rx",
	"usbip_dbg_vhci_sysfs",
	"usbip_dbg_vhci_tx",
	"usbip_dbg_xmit",
	"usb_stor_dbg",
	"user_log_dlm_error",
	"usnic_dbg",
	"usnic_err",
	"usnic_info",
	"uvc_printk",
	"uvc_trace",
	"v1printk",
	"v2printk",
	"v4l2_dbg",
	"v4l2_err",
	"v4l2_info",
	"v4l2_warn",
	"v4l_dbg",
	"v4l_err",
	"v4l_info",
	"v4l_warn",
	"var_printf",
	"vbi_dbg",
	"vbg_err",
	"v_dbg",
	"vbprintf",
	"vchiq_log_error",
	"vchiq_log_info",
	"vchiq_log_trace",
	"vchiq_log_warning",
	"vchiq_loud_error",
	"vcpu_debug",
	"vcpu_debug_ratelimited",
	"vcpu_err",
	"VCPU_EVENT",
	"VCPU_TP_PRINTK",
	"vcpu_unimpl",
	"vdbg_printk",
	"VDBG",
	"VDEB",
	"VDEBUG",
	"vdev_err",
	"vdev_neterr",
	"vdev_netwarn",
	"vdev_warn",
	"vdprintf",
	"VDBG",
	"VDEB",
	"v_err",
	"verbose",
	"verbose_debug",
	"verbose_printk",
	"vfprintf",
	"vfp_panic",
	"vgaarb_dbg",
	"vgaarb_err",
	"vgaarb_info"
	"video_dbg",
	"vin_dbg",
	"vin_err",
	"viodbg",
	"VLDBG",
	"VMM_DEBUG",
	"vmci_ioctl_err",
	"vpe_dbg",
	"vpe_err",
	"vpfe_dbg",
	"vpfe_err",
	"vpfe_info",
	"vpif_dbg",
	"vpif_err",
	"vpr_info",
	"vpr_info_dq",
	"vprint",
	"VPRINTK",
	"vprintf",
	"vprintk",
	"VPRINTK",
	"vprintk_emit",
	"vq_err",
	"vsnprintf",
	"vsprintf",
	"v_warn",
	"wait_err",
	"wait_warn",
	"warn",
	"WARN",
	"WARN_FUNC",
	"warning",
	"WARNING",
	"warn_invalid_dmar",
	"WARN_ON",
	"WARN_ONCE",
	"WARN_ON_ONCE",
	"__WARN_printf",
	"WARN_RATELIMIT",
	"warnx",
	"WASM",
	"wcn36xx_dbg",
	"wcn36xx_err",
	"wcn36xx_info",
	"wcn36xx_warn",
	"whc_hw_error",
	"wil_dbg_fw",
	"wil_dbg_irq",
	"wil_dbg_misc",
	"wil_dbg_pm",
	"wil_dbg_ratelimited",
	"wil_dbg_txrx",
	"wil_dbg_wmi",
	"wil_err",
	"wil_err_fw",
	"__wil_err_ratelimited",
	"wil_info",
	"wiphy_dbg",
	"wiphy_debug",
	"wiphy_err",
	"wiphy_info",
	"wiphy_notice",
	"wiphy_warn",
	"wl1251_debug",
	"wl1251_error",
	"wl1251_info",
	"wl1251_notice",
	"wl1251_warning",
	"wl1271_debug",
	"wl1271_error",
	"wl1271_info",
	"wl1271_notice",
	"wl1271_warning",
	"WRN_MSG",
	"xasprintf",
	"xdi_dbg_xlog",
	"xenbus_dev_error",
	"xenbus_dev_fatal",
	"xenbus_printf",
	"xen_raw_console_write",
	"xen_raw_printk",
	"xfs_alert",
	"xfs_crit",
	"xfs_info",
	"xfs_debug",
	"xfs_emerg",
	"xfs_notice",
	"xfs_warn",
	"XFS_CORRUPTION_ERROR",
	"XFS_ERROR_REPORT",
	"xhci_dbg",
	"xhci_dbg_trace",
	"xhci_err",
	"xhci_info",
	"xhci_warn",
	"XICS_DBG",
	"xmon_printf",
	"XPRINTK",
	"XXDEBUG",
	"YYFPRINTF",
	"zconf_error",
	"z_error",
	"zip_dbg",
	"zip_err",
	"zip_msg",
	"ZMII_DBG",
	"ZMII_DBG2",
	"zpa2326_dbg",
	"zpa2326_err",
	"zpa2326_warn",
	"zpci_err",
	"zswap_pool_debug",
};

static uint8_t mapping[256] ALIGNED(64);

static void set_mapping(void)
{
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(mapping); i++) {
		mapping[i] = BAD_MAPPING;
	}
	for (i = 'a'; i <= 'z'; i++) {
		mapping[i] = i - 'a';
	}
	for (i = 'A'; i <= 'Z'; i++) {
		mapping[i] = i - 'A';
	}
	for (i = '0'; i <= '9'; i++) {
		mapping[i] = 26;
	}
	mapping['_'] = 26;
}

static inline get_char_t CONST PURE HOT map(register const get_char_t ch)
{
	return mapping[ch];
}

/*
 *  Get length of token
 */
static inline size_t CONST PURE HOT token_len(register token_t *t)
{
	return t->ptr - t->token;
}

/*
 *  djb2a()
 *	relatively fast string hash
 */
static inline uint32_t TARGET_CLONES CONST PURE HOT djb2a(register const char *str)
{
        register uint32_t c;
        register uint32_t hash = 5381;

        while (LIKELY(c = *str++))
                hash = (hash * 33) ^ c;

        return hash & HASH_MASK;
}

static int parse_file(char *RESTRICT path, const mqd_t mq);

static void NORETURN out_of_memory(void)
{
	asm ("");	/* Stops inlining */
	fprintf(stderr, "Out of memory performing an allocation\n");
	exit(EXIT_FAILURE);
}

/*
 *  index_unpack_ptr()
 *	gcc-9 really dislikes taking the address of an element
 *	from a packed struct. However, to keep the cache hit
 *	low, the misalignment vs cache penalty is worthwhile.
 *	This is a horrible hack to silence the warnings. I'm sure
 *	gcc will figure this out sometime in the future.
 *	As it stands, this inlined function has no overhead as
 *	the optimizer does the right thing.
 */
static inline index_t *index_unpack_ptr(
	register word_node_t *RESTRICT node,
	register get_char_t ch)
{
	register void *vptr = (void *)&node->word_node_index[ch];

	return (index_t *)vptr;		/* Cast away our sins */
}

static inline void HOT add_word(
	register char *RESTRICT str,
	register word_node_t *RESTRICT node,
	register word_node_t *RESTRICT node_heap,
	register word_node_t **RESTRICT node_heap_next,
	const ssize_t heap_size)
{
	register get_char_t ch;

	if ((*node_heap_next - node_heap) >= heap_size)
		out_of_memory();

	ch = map(*str);

	if (LIKELY(ch != BAD_MAPPING)) {
		register index_t *RESTRICT ptr = index_unpack_ptr(node, ch);
		register word_node_t *new_node;
#if defined(PACKED_INDEX)
		register uint32_t index32 = ((uint32_t)ptr->hi8 << 16) | ptr->lo16;
#else
		register uint32_t index32 = ptr->lo32;
#endif

		if (index32) {
			new_node = &node_heap[index32];
		} else {
			new_node = *node_heap_next;
			index32 = new_node - node_heap;
			(*node_heap_next)++;

#if defined(PACKED_INDEX)
			ptr->hi8 = index32 >> 16;
			ptr->lo16 = index32;
#else
			ptr->lo32 = index32;
#endif
		}
		add_word(++str, new_node, node_heap, node_heap_next, heap_size);
	} else {
		node->eow = true;
	}
}

static inline bool HOT find_word(
	register const char *RESTRICT word,
	register word_node_t *RESTRICT node,
	register word_node_t *RESTRICT node_heap)
{
	for (;;) {
		register get_char_t ch;
		register index_t *ptr;
		register uint32_t index32;

		if (UNLIKELY(!node))
			return false;
		ch = *word;
		if (!ch)
			return node->eow;
		ch = map(ch);
		if (LIKELY(ch != BAD_MAPPING)) {
			ptr = index_unpack_ptr(node, ch);
#if defined(PACKED_INDEX)
			index32 = ((uint32_t)ptr->hi8 << 16) | ptr->lo16;
#else
			index32 = ptr->lo32;
#endif
			node = index32 ? &node_heap[index32] : NULL;
			word++;
		} else {
			return true;
		}
	}
}

static inline int read_dictionary(const char *dictfile)
{
	int fd;
	char *ptr, *dict, *dict_end;
	struct stat buf;
	char buffer[4096];
	const char *buffer_end = buffer + (sizeof(buffer)) - 1;

	fd = open(dictfile, O_RDONLY);
	if (fd < 0) {
		(void)snprintf(buffer, sizeof(buffer), "/snap/kernelscan/current/%s", dictfile);
		fd = open(buffer, O_RDONLY);
		if (fd < 0)
			return -1;
	}
	if (fstat(fd, &buf) < 0) {
		(void)close(fd);
		return -1;
	}

	ptr = dict = mmap(NULL, buf.st_size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
	if (dict == MAP_FAILED) {
		(void)close(fd);
		return -1;
	}
	dict_end = dict + buf.st_size;

	while (ptr < dict_end) {
		char *bptr = buffer;

		while (ptr < dict_end && bptr < buffer_end && *ptr != '\n') {
			*bptr++ = *ptr++;
		}
		dict_size += bptr - buffer;
		*bptr = '\0';
		ptr++;
		words++;
		add_word(buffer, word_nodes, word_node_heap, &word_node_heap_next, WORD_NODES_HEAP_SIZE);
	}
	(void)munmap(dict, buf.st_size);
	(void)close(fd);

	return 0;
}

static inline void HOT add_bad_spelling(const char *word, const size_t len)
{
	register hash_entry_t **head, *he;

	if (find_word(word, printk_nodes, printk_node_heap))
		return;

	bad_spellings_total++;
	head = &hash_bad_spellings[djb2a(word)];
	for (he = *head; he; he = he ->next) {
		if (!__builtin_strcmp(he->token, word))
			return;
	}
	he = malloc(sizeof(*he) + len);
	if (UNLIKELY(!he))
		out_of_memory();

	he->next = *head;
	*head = he;
	__builtin_memcpy(he->token, word, len);
	bad_spellings++;
}

static void TARGET_CLONES HOT check_words(token_t *token)
{
	register char *p1 = token->token, *p2, *p3;

	p3 = p1 + token_len(token);

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
			if (!find_word(p1, word_nodes, word_node_heap))
				add_bad_spelling(p1, 1 + p2 - p1);
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
	parser_t *RESTRICT p,
	unsigned char *RESTRICT data,
	unsigned char *RESTRICT data_end,
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
static inline get_char_t HOT get_char(register parser_t *p)
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
	//if (LIKELY(p->ptr > p->data))
	p->ptr--;
}

static int HOT CONST PURE cmp_format(const void *RESTRICT p1, const void *RESTRICT p2)
{
	const format_t *RESTRICT f1 = (const format_t *RESTRICT )p1;
	const format_t *RESTRICT f2 = (const format_t *RESTRICT )p2;

	register const size_t l1 = f1->len;
	register const size_t l2 = f2->len;

	if (l1 < l2)
		return 1;
	if (l1 > l2)
		return -1;
	return strcmp(f1->format, f2->format);
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
	int ret;

	ret = posix_memalign((void **)&t->token, 64, TOKEN_CHUNK_SIZE);
	if (ret != 0)
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
	/* No more space, add more space */
	ptrdiff_t diff = t->ptr - t->token;

	t->len += TOKEN_CHUNK_SIZE;
	t->token_end += TOKEN_CHUNK_SIZE;
	t->token = realloc(t->token, t->len);
	if (UNLIKELY(!t->token))
		out_of_memory();
	t->ptr = t->token + diff;
}

/*
 *  Append a single character to the token
 */
static inline void HOT token_append(register token_t *t, register const get_char_t ch)
{
	if (LIKELY(t->ptr < (t->token_end))) {
		*(t->ptr++) = ch;
	} else {
		token_expand(t);
		*(t->ptr++) = ch;
	}
}

static inline void HOT token_eos(token_t *t)
{
	*(t->ptr) = '\0';
}

static inline void HOT token_cat_str(register token_t *RESTRICT t, register const char *RESTRICT str)
{
	while (*str) {
		token_append(t, *str);
		str++;
	}
	token_eos(t);
}

static get_char_t HOT skip_macros(register parser_t *p)
{
	bool continuation = false;

	for (;;) {
		register get_char_t ch;

		ch = get_char(p);
		if (ch == '\n') {
			lines++;
			lineno++;
			if (!continuation)
				return ch;
			continuation = false;
		} else if (ch == '\\') {
			continuation = true;
		} else if (UNLIKELY(ch == PARSER_EOF))
			break;
	}
	return PARSER_EOF;
}

/*
 *  Parse C comments and just throw them away
 */
static get_char_t HOT TARGET_CLONES skip_comments(parser_t *p)
{
	register get_char_t ch, nextch;

	nextch = get_char(p);

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

			if (UNLIKELY(ch == '*')) {
				ch = get_char(p);

				if (LIKELY(ch == '/'))
					return PARSER_COMMENT_FOUND;
				else if (UNLIKELY(ch == PARSER_EOF))
					return ch;

				unget_char(p);
			}
			if (UNLIKELY(ch == PARSER_EOF))
				return ch;
		}
	}
	if (UNLIKELY(nextch == PARSER_EOF))
		return nextch;

	/* Not a comment, push back */
	unget_char(p);

	return PARSER_OK;
}

/*
 *  Parse an integer.  This is fairly minimal as the
 *  kernel doesn't have floats or doubles, so we
 *  can just parse decimal, octal or hex values.
 */
static get_char_t HOT TARGET_CLONES parse_number(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	bool ishex = false;
	bool isoct = false;

	/*
	 *  Crude way to detect the kind of integer
	 */
	if (LIKELY(ch == '0')) {
		register get_char_t nextch1, nextch2;

		token_append(t, ch);

		nextch1 = get_char(p);

		if (nextch1 >= '0' && nextch1 <= '8') {
			/* Must be an octal value */
			ch = nextch1;
			isoct = true;
		} else if (nextch1 == 'x' || nextch1 == 'X') {
			/* Is it hexadecimal? */
			nextch2 = get_char(p);

			if (isxdigit(nextch2)) {
				/* Hexadecimal */
				token_append(t, nextch1);
				ch = nextch2;
				ishex = true;
			} else if (LIKELY(nextch2 != PARSER_EOF)) {
				/* Nope */
				unget_char(p);
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			} else {
				unget_char(p);
				token_eos(t);
				return PARSER_OK;
			}
		} else if (LIKELY(nextch1 != PARSER_EOF)) {
			unget_char(p);
			token_eos(t);
			return PARSER_OK;
		} else {
			token_append(t, ch);
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
static get_char_t HOT parse_identifier(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	t->type = TOKEN_IDENTIFIER;
	token_append(t, ch);

	for (;;) {
		ch = get_char(p);
		register uint8_t ch8 = (uint8_t)ch;

		if (UNLIKELY(is_not_identifier[ch8])) {
			unget_char(p);
			token_eos(t);
			return PARSER_OK;
		}
		token_append(t, ch);
	}
}

/*
 *  Handle escape char deletion when at the end of a literal string,
 *  need to transform:
 * 	"foo\n" -> "foo" 
 * 	"foo\nbar" -> "foo bar"
 *	"foo\n"<whitespaces>"bar" -> "foo "<whitespaces>"bar"
 */
static inline void literal_peek(
	parser_t *RESTRICT p,
	token_t *RESTRICT t,
	const get_char_t literal)
{
	register get_char_t ch;
	uint32_t got;

	ch = get_char(p);
	if (UNLIKELY(ch != literal)) {
		unget_char(p);
		token_append(t, ' ');
		return;
	}
	got = 1;
	for (;;) {
		got++;
		ch = get_char(p);
		if (LIKELY(ch == literal)) {
			token_append(t, ' ');
			break;
		} else if (UNLIKELY(ch == TOKEN_WHITE_SPACE)) {
			continue;
		} else if (UNLIKELY(ch == PARSER_EOF)) {
			break;
		}
		break;
	}
	while (got) {
		unget_char(p);
		got--;
	}
}

/*
 *  Parse literal strings
 */
static get_char_t TARGET_CLONES parse_literal(
	parser_t *RESTRICT p,
	token_t *RESTRICT t,
	const get_char_t literal,
	const token_type_t type)
{
	t->type = type;

	token_append(t, literal);

	for (;;) {
		register get_char_t ch = get_char(p);

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
					literal_peek(p, t, literal);
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
				if (LIKELY(ch != PARSER_EOF)) {
					token_append(t, ch);
					continue;
				}
				token_eos(t);
				return ch;
			}
		}

		if (UNLIKELY(ch == literal)) {
			token_append(t, ch);
			token_eos(t);
			return PARSER_OK;
		}
		if (UNLIKELY(ch == PARSER_EOF)) {
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
static inline get_char_t parse_op(parser_t *RESTRICT p, token_t *RESTRICT t, const get_char_t op)
{
	token_append(t, op);

	if (get_char(p) == op) {
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
static inline get_char_t parse_minus(parser_t *RESTRICT p, token_t *RESTRICT t, const get_char_t op)
{
	register get_char_t ch;

	token_append(t, op);

	ch = get_char(p);

	if (ch == op) {
		token_append(t, ch);
		token_eos(t);
		return PARSER_OK;
	}

	if (LIKELY(ch == '>')) {
		token_append(t, ch);
		token_eos(t);
		t->type = TOKEN_ARROW;
		return PARSER_OK;
	}

	unget_char(p);
	token_eos(t);
	return PARSER_OK;
}

static inline get_char_t parse_skip_comments(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	get_char_t ret = skip_comments(p);

	if (ret == PARSER_COMMENT_FOUND) {
		ret |= PARSER_CONTINUE;
		return ret;
	}
	if (UNLIKELY(ret == PARSER_EOF))
		return ret;

	token_append(t, ch);
	token_eos(t);
	return PARSER_OK;
}

static inline get_char_t parse_simple(token_t *t, get_char_t ch, const token_type_t type)
{
	token_append(t, ch);
	token_eos(t);
	t->type = type;
	return PARSER_OK;
}

static inline get_char_t parse_hash(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;
	(void)ch;

	skip_macros(p);
	token_clear(t);

	return PARSER_OK;
}

static inline get_char_t parse_paren_opened(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_PAREN_OPENED);
}

static inline get_char_t parse_paren_closed(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_PAREN_CLOSED);
}


static inline get_char_t parse_square_opened(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_SQUARE_OPENED);
}

static inline get_char_t parse_square_closed(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_SQUARE_CLOSED);
}

static inline get_char_t parse_less_than(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_LESS_THAN);
}

static inline get_char_t parse_greater_than(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_GREATER_THAN);
}

static inline get_char_t parse_comma(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_COMMA);
}

static inline get_char_t parse_terminal(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	return parse_simple(t, ch, TOKEN_TERMINAL);
}

static inline get_char_t parse_misc_char(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;

	token_append(t, ch);
	token_eos(t);
	return PARSER_OK;
}

static inline get_char_t parse_literal_string(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	return parse_literal(p, t, ch, TOKEN_LITERAL_STRING);
}

static inline get_char_t parse_literal_char(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	return parse_literal(p, t, ch, TOKEN_LITERAL_CHAR);
}

static inline get_char_t parse_backslash(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
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

static inline get_char_t parse_newline(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	lines++;
	lineno++;
	return parse_backslash(p, t, ch);
}

static inline get_char_t parse_eof(parser_t *RESTRICT p, token_t *RESTRICT t, register get_char_t ch)
{
	(void)p;
	(void)t;
	(void)ch;

	return PARSER_EOF;
}

static inline get_char_t TARGET_CLONES parse_whitespace(
	parser_t *RESTRICT p,
	token_t *RESTRICT t,
	const get_char_t ch)
{
	(void)p;

	t->type = TOKEN_IDENTIFIER;
	token_append(t, ch);

	for (;;) {
		register uint8_t ch8;

		ch8 = (uint8_t)get_char(p);
		if (is_not_whitespace[ch8])
			break;
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
	['_'] = parse_identifier,
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
static get_char_t HOT get_token(register parser_t *RESTRICT p, register token_t *RESTRICT t)
{
	for (;;) {
		register get_char_t ret, ch = get_char(p);
		register get_token_action_t action = get_token_actions[ch];

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
	register size_t len = token_len(t);

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
	token_t *RESTRICT token,
	token_t *RESTRICT token_to_add)
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
	token_t *RESTRICT token,
	token_t *RESTRICT token_to_add)
{
	if (token_to_add->type == TOKEN_LITERAL_STRING)
		token_cat_str(token, token_to_add->token);
}

static void TARGET_CLONES strip_format(char *line)
{
	register char *ptr1 = line, *ptr2 = line;

	while (*ptr1) {
		if (UNLIKELY((*ptr1 == '%') && *(ptr1 + 1))) {
			register size_t i;

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
static get_char_t HOT TARGET_CLONES parse_kernel_message(
	const char *RESTRICT path,
	bool *RESTRICT source_emit,
	parser_t *RESTRICT p,
	token_t *RESTRICT t,
	token_t *RESTRICT line,
	token_t *RESTRICT str)
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
		get_char_t ret = get_token(p, t);

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
					check_words(line);
				else {
					char *ptr;
					if (! *source_emit) {
						if (opt_flags & OPT_SOURCE_NAME)
							printf("Source: %s\n", path);
						*source_emit = true;
					}
					if (opt_flags & OPT_FORMAT_STRIP)
						strip_format(line->token);

					for (ptr = line->token; isblank(*ptr); ptr++)
						;

					printf(" %s%s\n", ptr, (opt_flags & OPT_LITERAL_STRINGS) ? "" : ";");
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
				register size_t len = token_len(line);

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
 *  Parse input looking for printk like function calls
 */
static void parse_kernel_messages(
	const char *RESTRICT path,
	unsigned char *RESTRICT data,
	unsigned char *RESTRICT data_end,
	token_t *RESTRICT t,
	token_t *RESTRICT line,
	token_t *RESTRICT str)
{
	parser_t p;

	parser_new(&p, data, data_end, true);
	bool source_emit = false;

	token_clear(t);

	while ((get_token(&p, t)) != PARSER_EOF) {
		if ((t->type == TOKEN_IDENTIFIER) &&
		    (find_word(t->token, printk_nodes, printk_node_heap))) {
			parse_kernel_message(path, &source_emit, &p, t, line, str);
			//source_emit = true;
		}
		token_clear(t);
	}

	if (opt_flags & OPT_CHECK_WORDS)
		return;
	if (source_emit && (opt_flags & OPT_SOURCE_NAME))
		putchar('\n');
}

/*
 *  Parse input looking for literal strings
 */
static void parse_literal_strings(
	const char *RESTRICT path,
	unsigned char *RESTRICT data,
	unsigned char *RESTRICT data_end,
	token_t *RESTRICT t,
	token_t *RESTRICT line,
	token_t *RESTRICT str)
{
	parser_t p;

	(void)path;
	(void)line;
	(void)str;

	parser_new(&p, data, data_end, true);

	token_clear(t);

	while ((get_token(&p, t)) != PARSER_EOF) {
		if (t->type == TOKEN_LITERAL_STRING)
			check_words(t);
		token_clear(t);
	}
}

static void show_usage(void)
{
	fprintf(stderr, "kernelscan: the fast kernel source message scanner\n\n");
	fprintf(stderr, "kernelscan [options] path\n");
	fprintf(stderr, "  -c     check words in dictionary\n");
	fprintf(stderr, "  -e     strip out C escape sequences\n");
	fprintf(stderr, "  -f     replace kernel %% format specifiers with a space\n");
	fprintf(stderr, "  -h     show this help\n");
	fprintf(stderr, "  -k     same as -ceflsx\n");
	fprintf(stderr, "  -l     scan all literal strings and not print statements\n");
	fprintf(stderr, "  -n     find messages with missing \\n newline\n");
	fprintf(stderr, "  -s     just print literal strings\n");
	fprintf(stderr, "  -x     exclude the source file name from the output\n");
}

static int parse_dir(char *RESTRICT path, const mqd_t mq)
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

		if (LIKELY(d->d_name[0] != '.')) {
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
			parse_file(filepath, mq);
		}
	}
	(void)closedir(dp);

	return 0;
}

static int HOT parse_file(
	char *RESTRICT path,
	const mqd_t mq)
{
	struct stat buf;
	int fd;
	int rc = 0;

	const parse_func_t parse_func = (opt_flags & OPT_PARSE_STRINGS) ?
		parse_literal_strings : parse_kernel_messages;

	fd = open(path, O_RDONLY | O_NOATIME);
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
		register size_t len = __builtin_strlen(path);

		if (LIKELY(((len >= 2) && !__builtin_strcmp(path + len - 2, ".c")) ||
		    ((len >= 2) && !__builtin_strcmp(path + len - 2, ".h")) ||
		    ((len >= 4) && !__builtin_strcmp(path + len - 4, ".cpp")))) {
			if (LIKELY(buf.st_size > 0)) {
				msg_t msg;

				//(void)posix_fadvise(fd, 0, buf.st_size, POSIX_FADV_SEQUENTIAL);
				msg.data = mmap(NULL, (size_t)buf.st_size, PROT_READ,
					MAP_PRIVATE | MAP_POPULATE, fd, 0);
				if (UNLIKELY(msg.data == MAP_FAILED)) {
					(void)close(fd);
					fprintf(stderr, "Cannot mmap %s, errno=%d (%s)\n",
						path, errno, strerror(errno));
					return -1;
				}
				bytes_total += buf.st_size;

				msg.parse_func = parse_func;
				msg.size = buf.st_size;
				strncpy(msg.filename, path, sizeof(msg.filename) - 1);
				mq_send(mq, (char *)&msg, sizeof(msg), 1);
			}
			files++;
		}
		(void)close(fd);
	} else {
		(void)close(fd);
		if (S_ISDIR(buf.st_mode))
			rc = parse_dir(path, mq);
	}
	return rc;
}


static void *reader(void *arg)
{
	static void *nowt = NULL;
	const context_t *ctxt = arg;
	msg_t msg = { NULL, 0, NULL, "" };

	parse_file(ctxt->path, ctxt->mq);
	mq_send(ctxt->mq, (char *)&msg, sizeof(msg), 1);

	return &nowt;
}

static int parse_path(
	char *path,
	token_t *RESTRICT t,
	token_t *RESTRICT line,
	token_t *RESTRICT str)
{
	mqd_t mq = -1;
	struct mq_attr attr;
	char mq_name[64];
	int rc;
	context_t ctxt;
	pthread_t pthread;

	(void)snprintf(mq_name, sizeof(mq_name), "/kernelscan-%i", getpid());

	attr.mq_flags = 0;
	attr.mq_maxmsg = 10;
	attr.mq_msgsize = sizeof(msg_t);
	attr.mq_curmsgs = 0;

	mq = mq_open(mq_name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR, &attr);
	if (mq < 0)
		return -1;

	ctxt.path = path;
	ctxt.mq = mq;

	rc = pthread_create(&pthread, NULL, reader, &ctxt);
	if (rc) {
		rc = -1;
		goto err;
	}

	for (;;) {
		msg_t msg;

		rc = mq_receive(mq, (char *)&msg, sizeof(msg), NULL);
		if (UNLIKELY(rc < 0))
			break;
		if (UNLIKELY(msg.data == 0))
			break;

		__builtin_prefetch(msg.data, 0, 3);
		__builtin_prefetch((uint8_t *)msg.data + 64, 0, 3);
		msg.parse_func(msg.filename, msg.data, (uint8_t *)msg.data + msg.size, t, line, str);
		(void)munmap(msg.data, msg.size);
	}

	rc = 0;
err:
	(void)pthread_join(pthread, NULL);
	(void)mq_close(mq);
	(void)mq_unlink(mq_name);

	return rc;
}

static int cmpstr(const void *p1, const void *p2)
{
	return strcmp(* (char * const *) p1, * (char * const *) p2);
}

static void dump_bad_spellings(void)
{
	register size_t i, j;
	register char **bad_spellings_sorted;
	const size_t sz = bad_spellings * sizeof(char *);

	bad_spellings_sorted = malloc(sz);
	if (!bad_spellings_sorted)
		out_of_memory();

	for (i = 0, j = 0; i < SIZEOF_ARRAY(hash_bad_spellings); i++) {
		register hash_entry_t *he = hash_bad_spellings[i];

		while (he) {
			hash_entry_t *next = he->next;
			bad_spellings_sorted[j++] = he->token;
			he = next;
		}
	}

	qsort(bad_spellings_sorted, j, sizeof(char *), cmpstr);

	for (i = 0; i < bad_spellings; i++) {
		register char *ptr = bad_spellings_sorted[i];
		hash_entry_t *const he = (hash_entry_t *)(ptr - sizeof(hash_entry_t));
		register char ch;

		while ((ch = *(ptr++))) {
			putchar(ch);
		}
		putchar('\n');

		free(he);
	}

	free(bad_spellings_sorted);
}

static inline void load_printks(void)
{
	size_t i;

	for (i = 0; i < SIZEOF_ARRAY(printks); i++) {
		add_word(printks[i], printk_nodes, printk_node_heap, &printk_node_heap_next, PRINTK_NODES_HEAP_SIZE);
	}
}

static void set_is_not_whitespace(void)
{
	memset(is_not_whitespace, true, sizeof(is_not_whitespace));
	is_not_whitespace[' '] = false;
	is_not_whitespace['\t'] = false;
}

static void set_is_not_identifier(void)
{
	size_t i;

	memset(is_not_identifier, true, sizeof(is_not_identifier));
	for (i = 0; i < 26; i++) {
		is_not_identifier[i + 'a'] = false;
		is_not_identifier[i + 'A'] = false;
	}
	for (i = 0; i < 10; i++) {
		is_not_identifier[i + '0'] = false;
	}
	is_not_identifier['_'] = false;
}

/*
 *  Scan kernel source for printk like statements
 */
int main(int argc, char **argv)
{
	token_t t, line, str;
	double t1, t2;
	static char buffer[65536];

	token_cat = token_cat_normal;

	for (;;) {
		int c = getopt(argc, argv, "cefhklnsx");
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
		case 'k':
			opt_flags |= (OPT_CHECK_WORDS |
				      OPT_ESCAPE_STRIP |
				      OPT_FORMAT_STRIP |
				      OPT_LITERAL_STRINGS |
				      OPT_PARSE_STRINGS);
			opt_flags &= ~OPT_SOURCE_NAME;
			break;
		case 'l':
			opt_flags |= OPT_PARSE_STRINGS;
			break;
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

	set_is_not_whitespace();
	set_is_not_identifier();

	set_mapping();
	load_printks();
	(void)qsort(formats, SIZEOF_ARRAY(formats), sizeof(format_t), cmp_format);
	if (opt_flags & OPT_CHECK_WORDS) {
		int ret;

		ret = read_dictionary(dictionary);
		if (ret) {
			fprintf(stderr, "No dictionary found, expecting words in %s\n", dictionary);
			exit(EXIT_FAILURE);
		}
	}

	token_new(&t);
	token_new(&line);
	token_new(&str);

	fflush(stdout);
	setvbuf(stdout, buffer, _IOFBF, sizeof(buffer));

	t1 = gettime_to_double();
	while (argc > optind) {
		parse_path(argv[optind], &t, &line, &str);
		optind++;
	}
	t2 = gettime_to_double();

	token_free(&str);
	token_free(&line);
	token_free(&t);

	dump_bad_spellings();

	printf("\n%" PRIu32 " files scanned\n", files);
	printf("%" PRIu32 " lines scanned (%.3f"  " Mbytes)\n",
		lines, (float)bytes_total / (float)(1024 * 1024));
	printf("%" PRIu32 " print statements found\n", finds);
	if (words) {
		size_t nodes = word_node_heap_next - word_node_heap;
		printf("%" PRIu32 " words and %zd nodes in dictionary heap\n",
			words, nodes);
		printf("%" PRIu32 " chars mapped to %zd bytes of heap, ratio=1:%.2f\n",
			dict_size, nodes * sizeof(word_node_t),
			(float)nodes * sizeof(word_node_t) / dict_size);
	}
	printf("%zu printk style statements being searched\n",
		SIZEOF_ARRAY(printks));
	if (bad_spellings)
		printf("%" PRIu32 " unique bad spellings found (%" PRIu32 " non-unique)\n",
			bad_spellings, bad_spellings_total);
	printf("scanned %.2f lines per second\n",
		FLOAT_CMP(t1, t2) ? 0.0 : (double)lines / (t2 - t1));
	printf("(kernelscan " VERSION ")\n");

	fflush(stdout);
	exit(EXIT_SUCCESS);
}
