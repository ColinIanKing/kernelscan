/*
 * Copyright (C) 2012-2016 Canonical
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
#include <sys/mman.h>
#include <fcntl.h>

#define OPT_ESCAPE_STRIP	0x00000001

#define UNLIKELY(c)		__builtin_expect((c), 0)
#define LIKELY(c)		__builtin_expect((c), 1)

#define PARSER_OK		0
#define PARSER_COMMENT_FOUND	1

#define TOKEN_CHUNK_SIZE	(16384)

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
} token_type;

/*
 *  A token
 */
typedef struct {
	char *ptr;		/* Current end of the token during the lexical analysis */
	char *token;		/* The gathered string for this token */
	char *token_end;	/* end of the token */
	size_t len;		/* Length of the token buffer */
	token_type type;	/* The type of token we think it is */
} token;

/*
 *  Parser context
 */
typedef struct {
	char *ptr;		/* current data position */
	char *data;		/* The start data being parsed */
	char *data_end;		/* end of the data */
	bool skip_white_space;	/* Magic skip white space flag */
} parser;

static unsigned int hash_size;
static char stdin_buffer[65536];
static uint32_t opt_flags;
static uint64_t finds = 0;
static uint64_t files = 0;
static uint64_t lines = 0;

static char *funcs[] = {
	"printk",
	"PRINTK",
	"dprintk",
	"sdev_printk",
	"printf",
	"early_printk",
	"vprintk_emit",
	"vprintk",
	"printk_emit",
	"printk_once",
	"printk_deferred",
	"printk_deferred_once",
	"pr_emerg",
	"pr_alert",
	"pr_crit",
	"pr_err",
	"pr_warning",
	"pr_warn",
	"pr_notice",
	"pr_info",
	"pr_cont",
	"pr_devel",
	"pr_debug",
	"pr_emerg_once",
	"pr_alert_once",
	"pr_crit_once",
	"pr_err_once",
	"pr_warning_once",
	"pr_warn_once",
	"pr_notice_once",
	"pr_info_once",
	"pr_cont_once",
	"pr_devel_once",
	"pr_debug_once",
	"dynamic_pr_debug",
	"dev_vprintk_emit",
	"dev_printk_emit",
	"dev_printk",
	"dev_emerg",
	"dev_alert",
	"dev_crit",
	"dev_err",
	"dev_warn",
	"dev_dbg",
	"dev_notice",
	"dev_level_once",
	"dev_emerg_once",
	"dev_alert_once",
	"dev_crit_once",
	"dev_err_once",
	"dev_warn_once",
	"dev_notice_once",
	"dev_info_once",
	"dev_dbg_once",
	"dev_level_ratelimited",
	"dev_emerg_ratelimited",
	"dev_alert_ratelimited",
	"dev_crit_ratelimited",
	"dev_err_ratelimited",
	"dev_warn_ratelimited",
	"dev_notice_ratelimited",
	"dev_info_ratelimited",
	"dbg",
	"ACPI_ERROR",
	"ACPI_INFO",
	"ACPI_WARNING",
	"ACPI_EXCEPTION",
	"ACPI_BIOS_WARNING",
	"ACPI_BIOS_ERROR",
	"ACPI_ERROR_METHOD",
	"ACPI_DEBUG_PRINT",
	"ACPI_DEBUG_PRINT_RAW",
	"snd_printk",
	"srm_printk",
	"efi_printk",
	"netdev_printk",
	"netif_printk",
	"shost_printk",
	"scmd_printk",
	"asd_printk",
	"ecryptfs_printk",
	"ata_port_printk",
	"ata_link_printk",
	"ata_dev_printk",
	"no_printk",
	"iscsi_conn_printk",
	"sd_printk",
	"sr_printk",
	"st_printk",
	"DEBUG",
	NULL
};

#define TABLE_SIZE	(1000)

static char *hash_funcs[TABLE_SIZE];

static int parse_file(const char *path, token *t);

static uint32_t fnv1a(const char *str)
{
        const uint32_t fnv_prime = 16777619; /* 2^24 + 2^9 + 0x93 */
        register uint32_t c;
        register uint32_t hash = 5381;

        while ((c = *str++)) {
                hash ^= c;
                hash *= fnv_prime;
        }
        return hash;
}



/*
 *  Initialise the parser
 */
static inline void parser_new(parser *p, char *data, char *data_end, const bool skip_white_space)
{
	p->data = data;
	p->data_end = data_end;
	p->ptr = data;
	p->skip_white_space = skip_white_space;
}

/*
 *  Get next character from input stream
 */
static inline int get_char(parser *p)
{
	if (LIKELY(p->ptr < p->data_end))
		return *(p->ptr++);
	else
		return EOF;
}

/*
 *  Push character back onto the input
 *  stream (in this case, it is a simple FIFO stack
 */
static inline void unget_char(parser *p)
{
	if (LIKELY(p->ptr > p->data))
		p->ptr--;
}

/*
 *  Clear the token ready for re-use
 */
static inline void token_clear(token *t)
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
static void token_new(token *t)
{
	t->token = calloc(TOKEN_CHUNK_SIZE, 1);
	if (UNLIKELY(t->token == NULL)) {
		fprintf(stderr, "token_new: Out of memory!\n");
		exit(EXIT_FAILURE);
	}
	t->len = TOKEN_CHUNK_SIZE;
	token_clear(t);
}

/*
 *  Free the token
 */
static void token_free(token *t)
{
	free(t->token);
	t->token = NULL;
	t->ptr = NULL;
	t->len = 0;
	t->token_end = NULL;
	t->type = TOKEN_UNKNOWN;
}

static inline void token_expand(token *t)
{
	/* No more space, add 1K more space */
	ptrdiff_t diff = t->ptr - t->token;

	t->len += TOKEN_CHUNK_SIZE;
	t->token_end += TOKEN_CHUNK_SIZE;
	t->token = realloc(t->token, t->len);
	if (UNLIKELY(t->token == NULL)) {
		fprintf(stderr, "token_append: Out of memory!\n");
		exit(EXIT_FAILURE);
	}
	t->ptr = t->token + diff;
}

/*
 *  Append a single character to the token,
 *  we may run out of space, so this occasionally
 *  adds an extra 1K of token space for long tokens
 */
static void token_append(token *t, const int ch)
{
	if (UNLIKELY(t->ptr > t->token_end))
		token_expand(t);

	/* Enough space, just add char */
	*(t->ptr) = ch;
	t->ptr++;
	*(t->ptr) = 0;
}

/*
 *  Parse C comments and just throw them away
 */
static int skip_comments(parser *p)
{
	register int ch;
	int nextch;

	nextch = get_char(p);
	if (UNLIKELY(nextch == EOF))
		return EOF;

	if (nextch == '/') {
		do {
			ch = get_char(p);
			if (UNLIKELY(ch == EOF))
				return EOF;
		} while (ch != '\n');

		return PARSER_COMMENT_FOUND;
	}

	if (LIKELY(nextch == '*')) {
		for (;;) {
			ch = get_char(p);
			if (UNLIKELY(ch == EOF))
				return EOF;

			if (ch == '*') {
				ch = get_char(p);
				if (UNLIKELY(ch == EOF))
					return EOF;

				if (ch == '/')
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
static int parse_number(parser *p, token *t, int ch)
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
		if (UNLIKELY(nextch1 == EOF)) {
			token_append(t, ch);
			return PARSER_OK;
		}

		if (nextch1 >= '0' && nextch1 <= '8') {
			/* Must be an octal value */
			ch = nextch1;
			isoct = true;
		} else if (nextch1 == 'x' || nextch1 == 'X') {
			/* Is it hexadecimal? */
			nextch2 = get_char(p);
			if (UNLIKELY(nextch2 == EOF)) {
				unget_char(p);
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
				return PARSER_OK;
			}
		} else {
			unget_char(p);
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

		if (UNLIKELY(ch == EOF)) {
			unget_char(p);
			return PARSER_OK;
		}

		if (ishex) {
			if (isxdigit(ch)) {
				token_append(t, ch);
			} else {
				unget_char(p);
				return PARSER_OK;
			}
		} else if (isoct) {
			if (ch >= '0' && ch <= '8') {
				token_append(t, ch);
			} else {
				unget_char(p);
				return PARSER_OK;
			}
		} else {
			if (isdigit(ch)) {
				token_append(t, ch);
			} else {
				unget_char(p);
				return PARSER_OK;
			}
		}
	}
}

/*
 *  Parse identifiers
 */
static int parse_identifier(parser *p, token *t, int ch)
{
	token_append(t, ch);

	t->type = TOKEN_IDENTIFIER;

	for (;;) {
		ch = get_char(p);
		if (UNLIKELY(ch == EOF)) {
			break;
		}
		if (LIKELY(isalnum(ch) || ch == '_')) {
			token_append(t, ch);
		} else {
			unget_char(p);
			break;
		}
	}

	return PARSER_OK;
}

/*
 *  Parse literal strings
 */
static int parse_literal(
	parser *p,
	token *t,
	const int literal,
	const token_type type)
{
	t->type = type;

	token_append(t, literal);

	for (;;) {
		int ch = get_char(p);
		if (UNLIKELY(ch == EOF))
			return PARSER_OK;

		if (ch == '\\') {
			if (opt_flags & OPT_ESCAPE_STRIP) {
				ch = get_char(p);
				if (UNLIKELY(ch == EOF))
					return EOF;
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
				if (UNLIKELY(ch == EOF))
					return EOF;
				token_append(t, ch);
				continue;
			}
		}

		if (UNLIKELY(ch == literal)) {
			token_append(t, ch);
			return PARSER_OK;
		}

		token_append(t, ch);
	}

	return PARSER_OK;
}

/*
 *  Parse operators such as +, - which can
 *  be + or ++ forms.
 */
static inline int parse_op(parser *p, token *t, const int op)
{
	int ch;

	token_append(t, op);

	ch = get_char(p);
	if (UNLIKELY(ch == EOF))
		return PARSER_OK;

	if (ch == op) {
		token_append(t, op);
		return PARSER_OK;
	}

	unget_char(p);
	return PARSER_OK;
}

/*
 *  Parse -, --, ->
 */
static inline int parse_minus(parser *p, token *t, const int op)
{
	int ch;

	token_append(t, op);

	ch = get_char(p);
	if (UNLIKELY(ch == EOF))
		return PARSER_OK;

	if (ch == op) {
		token_append(t, ch);
		return PARSER_OK;
	}

	if (ch == '>') {
		token_append(t, ch);
		t->type = TOKEN_ARROW;
		return PARSER_OK;
	}

	unget_char(p);
	return PARSER_OK;
}

/*
 *  Gather a token from input stream
 */
static int get_token(parser *p, token *t)
{
	int ret;

	for (;;) {
		int ch = get_char(p);

		switch (ch) {
		case EOF:
			return EOF;

		/* Skip comments */
		case '/':
			ret = skip_comments(p);
			if (UNLIKELY(ret == EOF))
				return EOF;
			if (ret == PARSER_COMMENT_FOUND)
				continue;
			token_append(t, ch);
			return PARSER_OK;
		case '#':
			token_append(t, ch);
			t->type = TOKEN_CPP;
			return PARSER_OK;
		case '\n':
			lines++;
		case ' ':
		case '\t':
		case '\r':
		case '\\':
			if (opt_flags & OPT_ESCAPE_STRIP) {
				if (p->skip_white_space)
					continue;
				token_append(t, ch);
				t->type = TOKEN_WHITE_SPACE;
				return PARSER_OK;
			} else {
				if (p->skip_white_space)
					continue;
				token_append(t, ch);
				ch = get_char(p);
				if (ch == EOF)
					return EOF;
				token_append(t, ch);
				return PARSER_OK;
			}
			break;
		case '(':
			token_append(t, ch);
			t->type = TOKEN_PAREN_OPENED;
			return PARSER_OK;
		case ')':
			token_append(t, ch);
			t->type = TOKEN_PAREN_CLOSED;
			return PARSER_OK;
		case '[':
			token_append(t, ch);
			t->type = TOKEN_SQUARE_OPENED;
			return PARSER_OK;
		case ']':
			token_append(t, ch);
			t->type = TOKEN_SQUARE_CLOSED;
			return PARSER_OK;
		case '<':
			token_append(t, ch);
			t->type = TOKEN_LESS_THAN;
			return PARSER_OK;
		case '>':
			token_append(t, ch);
			t->type = TOKEN_GREATER_THAN;
			return PARSER_OK;
		case ',':
			token_append(t, ch);
			t->type = TOKEN_COMMA;
			return PARSER_OK;
		case ';':
			token_append(t, ch);
			t->type = TOKEN_TERMINAL;
			return PARSER_OK;
		case '{':
		case '}':
		case ':':
		case '~':
		case '?':
		case '*':
		case '%':
		case '!':
		case '.':
			token_append(t, ch);
			return PARSER_OK;
		case '0'...'9':
			return parse_number(p, t, ch);
			break;
		case 'a'...'z':
		case 'A'...'Z':
			return parse_identifier(p, t, ch);
			break;
		case '"':
			return parse_literal(p, t, ch, TOKEN_LITERAL_STRING);
		case '\'':
			return parse_literal(p, t, ch, TOKEN_LITERAL_CHAR);
		case '+':
		case '=':
		case '|':
		case '&':
			return parse_op(p, t, ch);
		case '-':
			return parse_minus(p, t, ch);
		}
	}

	return PARSER_OK;
}

/*
 *  Literals such as "foo" and 'f' sometimes
 *  need the quotes stripping off.
 */
static void literal_strip_quotes(token *t)
{
	size_t len = strlen(t->token);

	t->token[len-1] = 0;

	memmove(t->token, t->token + 1, len - 1);
}

/*
 *  Concatenate new string onto old. The old
 *  string can be NULL or an existing string
 *  on the heap.  This returns the newly
 *  concatenated string.
 */
static char *strdupcat(char *old, char *new)
{
	size_t len = strlen(new);
	char *tmp;

	if (UNLIKELY(old == NULL)) {
		tmp = malloc(len + 1);
		if (UNLIKELY(tmp == NULL)) {
			fprintf(stderr, "strdupcat(): Out of memory.\n");
			exit(EXIT_FAILURE);
		}
		strcpy(tmp, new);
	} else {
		size_t oldlen = strlen(old);
		tmp = realloc(old, oldlen + len + 1);
		if (UNLIKELY(tmp == NULL)) {
			fprintf(stderr, "strdupcat(): Out of memory.\n");
			exit(EXIT_FAILURE);
		}
		strcat(tmp, new);
	}

	return tmp;
}

/*
 *  Parse a kernel message, like printk() or dev_err()
 */
static int parse_kernel_message(const char *path, bool *source_emit, parser *p, token *t)
{
	bool got_string = false;
	bool emit = false;
	bool found = false;
	char *str = NULL;
	char *line = NULL;

	line = strdupcat(line, t->token);
	token_clear(t);
	if (UNLIKELY(get_token(p, t) == EOF)) {
		free(line);
		return EOF;
	}
	if (t->type != TOKEN_PAREN_OPENED) {
		free(line);
		for (;;) {
			if (UNLIKELY(get_token(p, t) == EOF))
				return EOF;
			if (t->type == TOKEN_TERMINAL)
				break;
		}
		return PARSER_OK;
	}
	line = strdupcat(line, t->token);
	token_clear(t);

	for (;;) {
		int ret = get_token(p, t);
		if (UNLIKELY(ret == EOF)) {
			free(line);
			free(str);
			return EOF;
		}

		/*
		 *  Hit ; so lets push out what we've parsed
		 */
		if (t->type == TOKEN_TERMINAL) {
			if (emit) {
				if (! *source_emit) {
					printf("Source: %s\n", path);
					*source_emit = true;
				}
				printf("%s;\n", line);
				finds++;
			}
			free(line);
			free(str);
			return PARSER_OK;
		}

		if (t->type == TOKEN_LITERAL_STRING) {
			literal_strip_quotes(t);
			str = strdupcat(str, t->token);

			if (!got_string)
				line = strdupcat(line, "\"");

			got_string = true;
			emit = true;
		} else {
			if (got_string)
				line = strdupcat(line, "\"");

			got_string = false;

			if (str) {
				found |= true;
				free(str);
				str = NULL;
			}
		}

		line = strdupcat(line, t->token);
		if (t->type == TOKEN_COMMA)
			line = strdupcat(line, " ");

		token_clear(t);
	}
	free(line);
}

/*
 *  Parse input looking for printk or dev_err calls
 */
static void parse_kernel_messages(const char *path, char *data, char *data_end, token *t)
{
	parser p;

	parser_new(&p, data, data_end, true);
	bool source_emit = false;

	token_clear(t);

	while ((get_token(&p, t)) != EOF) {
		register unsigned int h = fnv1a(t->token) % hash_size;
		char *hf = hash_funcs[h];

		if (hf && !strcmp(t->token, hf))
			parse_kernel_message(path, &source_emit, &p, t);
		else
			token_clear(t);
	}

	if (source_emit)
		putchar('\n');
}

static void show_usage(void)
{
	fprintf(stderr, "kernelscan: the fast kernel source message scanner\n\n");
	fprintf(stderr, "kernelscan [-e] path\n");
	fprintf(stderr, "  -e     strip out C escape sequences\n");
}

static int parse_dir(const char *path, token *t)
{
	DIR *dp;
	struct dirent *d;

	if ((dp = opendir(path)) == NULL) {
		fprintf(stderr, "Cannot open directory %s, errno=%d (%s)\n",
			path, errno, strerror(errno));
		return -1;
	}
	while ((d = readdir(dp)) != NULL) {
		char filepath[PATH_MAX];

		if (!strcmp(d->d_name, "."))
			continue;
		if (!strcmp(d->d_name, ".."))
			continue;

		snprintf(filepath, sizeof(filepath), "%s/%s", path, d->d_name);
		parse_file(filepath, t);
	}
	(void)closedir(dp);

	return 0;
}

static int parse_file(const char *path, token *t)
{
	struct stat buf;

	if (stat(path, &buf) < 0) {
		fprintf(stderr, "Cannot stat %s, errno=%d (%s)\n",
			path, errno, strerror(errno));
		return -1;
	}
	if (S_ISREG(buf.st_mode)) {
		size_t len = strlen(path);

		if (((len >= 2) && !strcmp(path + len - 2, ".c")) ||
		    ((len >= 2) && !strcmp(path + len - 2, ".h")) ||
		    ((len >= 4) && !strcmp(path + len - 4, ".cpp"))) {
			int fd;
			char *data;

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
			if (LIKELY(buf.st_size > 0)) {
				data = mmap(NULL, (size_t)buf.st_size, PROT_READ,
					MAP_SHARED | MAP_POPULATE, fd, 0);
				if (UNLIKELY(data == MAP_FAILED)) {
					fprintf(stderr, "Cannot mmap %s, errno=%d (%s)\n",
						path, errno, strerror(errno));
					(void)close(fd);
					return -1;
				}
				parse_kernel_messages(path, data, data + buf.st_size, t);
				(void)munmap(data, (size_t)buf.st_size);
			}
			(void)close(fd);
			files++;
		}
	} else if (S_ISDIR(buf.st_mode)) {
		return parse_dir(path, t);
	}
	return 0;
}

/*
 *  Scan kernel source for printk like statements
 */
int main(int argc, char **argv)
{
	size_t i;
	token t;

	for (;;) {
		int c = getopt(argc, argv, "eh");
		if (c == -1)
 			break;
		switch (c) {
		case 'e':
			opt_flags |= OPT_ESCAPE_STRIP;
			break;
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		default:
			show_usage();
			exit(EXIT_FAILURE);
		}
	}

	setvbuf(stdin, stdin_buffer, _IOFBF, sizeof stdin_buffer);

	/* Find optimal hash table size */
	for (hash_size = 684; hash_size < TABLE_SIZE; hash_size++) {
		bool collision = false;

		memset(hash_funcs, 0, sizeof(hash_funcs));

		for (i = 0; funcs[i]; i++) {
			unsigned int h = fnv1a(funcs[i]) % hash_size;

			if (hash_funcs[h]) {
				collision = true;
				break;
			}
			hash_funcs[h] = funcs[i];
		}
		if (!collision)
			break;
	}
	if (hash_size == TABLE_SIZE) {
		fprintf(stderr, "Increase TABLE_SIZE for hash table\n");
		exit(EXIT_FAILURE);
	}

	token_new(&t);
	while (argc > optind) {
		parse_file(argv[optind], &t);
		optind++;
	}
	token_free(&t);

	printf("\n%" PRIu64 " files scanned\n", files);
	printf("%" PRIu64 " lines scanned\n", lines);
	printf("%" PRIu64 " statements found\n", finds);

	exit(EXIT_SUCCESS);
}
