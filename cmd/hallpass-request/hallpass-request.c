// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// hallpass-request asks hallpass for access in advance: it turns its
// arguments into an execve of /proc/self/hallpass/request?... (or check?...)
// and the errno hallpass answers with into one line on stderr and an exit
// code. See docs/workstation/agents.md and internal/monitor/advance.go.

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PREFIX "/proc/self/hallpass/"

enum {
	EXIT_GRANTED = 0,
	EXIT_ALLOWED = 1,
	EXIT_USAGE = 2,
	EXIT_DENIED = 3,
	EXIT_TIMEOUT = 4,
	EXIT_WOULD_ASK = 5,
	EXIT_INVALID = 6,
	EXIT_NOT_MEDIATED = 7,
	EXIT_NO_HALLPASS = 8,
	EXIT_OTHER = 9,
};

static const char usage_line[] =
	"usage: hallpass-request [check] write PATH [--for DURATION] [--reason TEXT]\n";

static const char help_text[] =
	"Ask the hallpass user in advance for write access to PATH: a file, or a\n"
	"folder and everything below it when PATH ends in /** (quote it).\n"
	"check: only tell whether a request would ask the user.\n"
	"  --for DURATION  how long: 90s, 10m, 2h... (default: the session)\n"
	"  --reason TEXT   why, shown to the user as your own words\n"
	"Exit: 0 granted, 1 already allowed, 2 usage, 3 denied, 4 no answer in\n"
	"time, 5 (check) would ask, 6 invalid request, 7 files not mediated,\n"
	"8 not under hallpass, 9 other error.\n";

static int usage(void)
{
	fputs(usage_line, stderr);
	return EXIT_USAGE;
}

static int unreserved(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || (c != '\0' && strchr("-._~/", c));
}

// enclen returns the length of s percent-encoded.
static size_t enclen(const char *s)
{
	size_t n = 0;
	for (; *s; s++)
		n += unreserved((unsigned char)*s) ? 1 : 3;
	return n;
}

// encode appends s to p percent-encoded and returns the new end. Every
// byte but the unreserved ones and '/' is encoded: hallpass decodes the
// query (url.ParseQuery) before it looks at the path.
static char *encode(char *p, const char *s)
{
	static const char hex[] = "0123456789ABCDEF";
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (unreserved(c)) {
			*p++ = (char)c;
		} else {
			*p++ = '%';
			*p++ = hex[c >> 4];
			*p++ = hex[c & 15];
		}
	}
	return p;
}

int main(int argc, char **argv)
{
	int check = 0, opts = 1;
	const char *op = NULL, *path = NULL, *dur = NULL, *reason = NULL;

	if (argc < 2)
		return usage();
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		const char **val = NULL;
		if (opts && (!strcmp(a, "-h") || !strcmp(a, "--help"))) {
			fputs(usage_line, stdout);
			fputs(help_text, stdout);
			return 0;
		}
		if (opts && !strcmp(a, "--")) {
			opts = 0;
			continue;
		}
		if (opts && !strncmp(a, "--for", 5)) {
			val = &dur;
			a += 5;
		} else if (opts && !strncmp(a, "--reason", 8)) {
			val = &reason;
			a += 8;
		} else if (opts && a[0] == '-' && a[1] != '\0') {
			fprintf(stderr, "hallpass-request: unknown option %s\n", argv[i]);
			return usage();
		}
		if (val) {
			const char *name = argv[i];
			if (*a == '=') {
				a++;
			} else if (*a != '\0') {
				fprintf(stderr, "hallpass-request: unknown option %s\n", name);
				return usage();
			} else if (++i < argc) {
				a = argv[i];
			} else {
				fprintf(stderr, "hallpass-request: %s needs a value\n", name);
				return usage();
			}
			if (*a == '\0') {
				fprintf(stderr, "hallpass-request: empty value for %s\n", name);
				return usage();
			}
			*val = a;
			continue;
		}
		if (!op && !check && !strcmp(a, "check")) {
			check = 1;
		} else if (!op) {
			if (strcmp(a, "write") != 0) {
				fprintf(stderr, "hallpass-request: unknown operation %s (only write)\n", a);
				return usage();
			}
			op = a;
		} else if (!path) {
			if (*a == '\0') {
				fputs("hallpass-request: empty path\n", stderr);
				return usage();
			}
			path = a;
		} else {
			fprintf(stderr, "hallpass-request: one path only, got %s too (quote a path ending in /**)\n", a);
			return usage();
		}
	}
	if (!op || !path)
		return usage();

	// hallpass wants an absolute path: prefix a relative one with the
	// working directory, which hallpass would resolve it from anyway.
	char cwd[PATH_MAX] = "";
	if (path[0] != '/') {
		if (!getcwd(cwd, sizeof(cwd) - 1)) {
			fprintf(stderr, "hallpass-request: working directory: %s\n", strerror(errno));
			return EXIT_OTHER;
		}
		if (strcmp(cwd, "/") != 0)
			strcat(cwd, "/");
	}

	size_t n = strlen(PREFIX "request?op=") + enclen(op) +
		   strlen("&path=") + enclen(cwd) + enclen(path) +
		   (dur ? strlen("&for=") + enclen(dur) : 0) +
		   (reason ? strlen("&reason=") + enclen(reason) : 0);
	if (n >= PATH_MAX) {
		fprintf(stderr, "hallpass-request: invalid request: too long, %zu bytes encoded, at most %d\n", n, PATH_MAX - 1);
		return EXIT_INVALID;
	}
	char req[PATH_MAX];
	char *p = stpcpy(req, check ? PREFIX "check?op=" : PREFIX "request?op=");
	p = encode(p, op);
	p = stpcpy(p, "&path=");
	p = encode(p, cwd);
	p = encode(p, path);
	if (dur) {
		p = stpcpy(p, "&for=");
		p = encode(p, dur);
	}
	if (reason) {
		p = stpcpy(p, "&reason=");
		p = encode(p, reason);
	}
	*p = '\0';

	// hallpass never lets it run: the errno is the answer.
	extern char **environ;
	char *args[] = {"hallpass-request", NULL};
	execve(req, args, environ);

	const char *msg;
	int code;
	switch (errno) {
	case EALREADY:
		msg = "granted: go ahead";
		code = EXIT_GRANTED;
		break;
	case EEXIST:
		msg = check ? "allowed: go ahead" : "already allowed, nobody was asked: go ahead";
		code = EXIT_ALLOWED;
		break;
	case EPERM:
		msg = "denied by the user or a rule: do not write there, do not ask again";
		code = EXIT_DENIED;
		break;
	case ETIMEDOUT:
		msg = "denied: nobody answered in time";
		code = EXIT_TIMEOUT;
		break;
	case ENOMSG:
		msg = "not allowed yet: a request, or writing there, would ask the user";
		code = EXIT_WOULD_ASK;
		break;
	case EINVAL:
		msg = "invalid request: PATH takes no glob but a final /**, DURATION is like 90s, 10m or 2h";
		code = EXIT_INVALID;
		break;
	case ENAMETOOLONG:
		msg = "invalid request: too long";
		code = EXIT_INVALID;
		break;
	case ENOSYS:
		msg = "files are not mediated in this sandbox: nothing to ask";
		code = EXIT_NOT_MEDIATED;
		break;
	case ENOENT:
		msg = "not running under hallpass: nothing to ask";
		code = EXIT_NO_HALLPASS;
		break;
	default:
		fprintf(stderr, "hallpass-request: unexpected error: %s\n", strerror(errno));
		return EXIT_OTHER;
	}
	fprintf(stderr, "hallpass-request: %s\n", msg);
	return code;
}
