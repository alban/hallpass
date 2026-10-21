// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// hallpass-request asks hallpass for access in advance: it turns its
// arguments into an execve of /proc/self/hallpass/request?... (or check?...,
// release?...) and the errno hallpass answers with into one line on stderr
// and an exit code. See docs/workstation/agents.md and
// internal/monitor/advance.go.

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
	EXIT_NO_GRANT = 10,
};

static const char usage_line[] =
	"usage: hallpass-request [check] write|exec PATH [--for DURATION] [--reason TEXT]\n"
	"       hallpass-request [check] connect DEST [--for DURATION] [--reason TEXT]\n"
	"       hallpass-request release write|exec|connect PATH|DEST\n";

static const char help_text[] =
	"Ask the hallpass user in advance to:\n"
	"  write PATH     write a file, or a folder and everything below it when\n"
	"                 PATH ends in /** (quote it)\n"
	"  exec PROG      run a program: a path, a name looked up in $PATH, or\n"
	"                 DIR/** for every program below DIR\n"
	"  connect DEST   connect and send to network destinations, as hallpass\n"
	"                 --allow-net takes them: [tcp:|udp:]ADDR[/N][:PORT[-PORT]],\n"
	"                 * for any address, [IPv6], unix:/path, unix:/dir/**,\n"
	"                 unix:@name, unix:@prefix*; addresses, not host names\n"
	"check: only tell whether a request would ask the user.\n"
	"release: give back what a granted request asked for, exactly as asked.\n"
	"  --for DURATION  how long: 90s, 10m, 2h... (default: the session)\n"
	"  --reason TEXT   why, shown to the user as your own words\n"
	"Exit: 0 granted (or released), 1 already allowed, 2 usage, 3 denied,\n"
	"4 no answer in time, 5 (check) would ask, 6 invalid request, 7 not\n"
	"mediated, 8 not under hallpass, 9 other error, 10 (release) no such grant.\n";

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

// lookpath copies to buf, of PATH_MAX bytes, the first executable regular
// file named name in $PATH's absolute folders, as hallpass --allow-exec
// finds a program. It returns 0 if there is none.
static int lookpath(char *buf, const char *name)
{
	const char *dirs = getenv("PATH");
	struct stat st;

	while (dirs && *dirs) {
		size_t len = strcspn(dirs, ":");
		if (dirs[0] == '/' && len + 1 + strlen(name) < PATH_MAX) {
			memcpy(buf, dirs, len);
			buf[len] = '/';
			strcpy(buf + len + 1, name);
			if (stat(buf, &st) == 0 && S_ISREG(st.st_mode) && access(buf, X_OK) == 0)
				return 1;
		}
		dirs += len;
		if (*dirs == ':')
			dirs++;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *verb = "request", *op = NULL, *target = NULL, *dur = NULL, *reason = NULL;
	int opts = 1;

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
		if (!op && !strcmp(verb, "request") && (!strcmp(a, "check") || !strcmp(a, "release"))) {
			verb = a;
		} else if (!op) {
			if (strcmp(a, "write") != 0 && strcmp(a, "exec") != 0 && strcmp(a, "connect") != 0) {
				fprintf(stderr, "hallpass-request: unknown operation %s (write, exec or connect)\n", a);
				return usage();
			}
			op = a;
		} else if (!target) {
			if (*a == '\0') {
				fputs("hallpass-request: empty target\n", stderr);
				return usage();
			}
			target = a;
		} else {
			fprintf(stderr, "hallpass-request: one target only, got %s too (quote a path ending in /**)\n", a);
			return usage();
		}
	}
	if (!op || !target)
		return usage();
	int release = !strcmp(verb, "release"), net = !strcmp(op, "connect");
	if (release && (dur || reason)) {
		fputs("hallpass-request: release takes no --for or --reason\n", stderr);
		return usage();
	}

	// exec: a name is looked up in $PATH.
	char prog[PATH_MAX];
	if (!strcmp(op, "exec") && !strchr(target, '/')) {
		if (target[0] == '@') {
			fputs("hallpass-request: a group of programs cannot be asked for: name a program\n", stderr);
			return usage();
		}
		if (!lookpath(prog, target)) {
			fprintf(stderr, "hallpass-request: invalid request: %s not found in $PATH\n", target);
			return EXIT_INVALID;
		}
		target = prog;
	}

	// hallpass wants an absolute path: prefix a relative one with the
	// working directory, which hallpass would resolve it from anyway.
	char cwd[PATH_MAX] = "";
	if (!net && target[0] != '/') {
		if (!getcwd(cwd, sizeof(cwd) - 1)) {
			fprintf(stderr, "hallpass-request: working directory: %s\n", strerror(errno));
			return EXIT_OTHER;
		}
		if (strcmp(cwd, "/") != 0)
			strcat(cwd, "/");
	}

	const char *key = net ? "&dest=" : "&path=";
	size_t n = strlen(PREFIX) + strlen(verb) + strlen("?op=") + enclen(op) +
		   strlen(key) + enclen(cwd) + enclen(target) +
		   (dur ? strlen("&for=") + enclen(dur) : 0) +
		   (reason ? strlen("&reason=") + enclen(reason) : 0);
	if (n >= PATH_MAX) {
		fprintf(stderr, "hallpass-request: invalid request: too long, %zu bytes encoded, at most %d\n", n, PATH_MAX - 1);
		return EXIT_INVALID;
	}
	char req[PATH_MAX];
	char *p = stpcpy(req, PREFIX);
	p = stpcpy(p, verb);
	p = stpcpy(p, "?op=");
	p = encode(p, op);
	p = stpcpy(p, key);
	p = encode(p, cwd);
	p = encode(p, target);
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

	const char *what = net ? "connect there" : !strcmp(op, "exec") ? "run it" : "write there";
	const char *msg;
	int code;
	switch (errno) {
	case ECANCELED:
		msg = "released";
		code = EXIT_GRANTED;
		break;
	case ESRCH:
		msg = "no such grant: release names exactly what a granted request asked for";
		code = EXIT_NO_GRANT;
		break;
	case EALREADY:
		msg = "granted: go ahead";
		code = EXIT_GRANTED;
		break;
	case EEXIST:
		msg = !strcmp(verb, "check") ? "allowed: go ahead" : "already allowed, nobody was asked: go ahead";
		code = EXIT_ALLOWED;
		break;
	case EPERM:
		fprintf(stderr, "hallpass-request: denied by the user or a rule: do not %s, do not ask again\n", what);
		return EXIT_DENIED;
	case ETIMEDOUT:
		msg = "denied: nobody answered in time";
		code = EXIT_TIMEOUT;
		break;
	case ENOMSG:
		fprintf(stderr, "hallpass-request: not allowed yet: a request, or trying to %s, would ask the user\n", what);
		return EXIT_WOULD_ASK;
	case EINVAL:
		msg = net ? "invalid request: DEST is an address as hallpass --allow-net takes it (not a host name, not all), DURATION is like 90s, 10m or 2h"
			  : "invalid request: PATH takes no glob but a final /**, DURATION is like 90s, 10m or 2h";
		code = EXIT_INVALID;
		break;
	case ENAMETOOLONG:
		msg = "invalid request: too long";
		code = EXIT_INVALID;
		break;
	case ENOSYS:
		fprintf(stderr, "hallpass-request: %s is not mediated in this sandbox: nothing to ask\n", op);
		return EXIT_NOT_MEDIATED;
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
