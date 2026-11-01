/* EXPERIMENTAL, opt-in: the resident guard's thin client in C (source only; not in the npm package). It does what
 * bin/irontrellis-hook-client.mjs does without a Node start per call: the same command line and standard input as
 * `irontrellis-hook <agent> <event>`, one request to the daemon (`irontrellis-hook daemon`, src/daemon.ts), its reply
 * written as the hook would write it.
 *
 * It never decides anything itself. Whenever the daemon cannot give the hook's answer (no socket; a socket, its directory
 * or a directory above it that another user could change; a failed connection; a timeout; a reply it cannot read; the
 * daemon's own "run the hook" answer) it runs IRONTRELLISD_FALLBACK, the hook command (for example the absolute path of
 * irontrellis-hook), with `<agent> <event>` and the same standard input, and exits with its code. Without
 * IRONTRELLISD_FALLBACK such a call is refused (exit 2), never allowed.
 *
 * Socket: IRONTRELLISD_SOCKET, else $XDG_RUNTIME_DIR/irontrellis/irontrellisd.sock, else
 * $IRONTRELLIS_HOME/run/irontrellisd.sock, else $HOME/.irontrellis/run/irontrellisd.sock (the daemon's own rule).
 * Build: cc -O2 -Wall -Wextra -o irontrellis-hook-client packages/hooks/contrib/irontrellis-hook-client.c */
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* The variables the hook reads (src/daemon.ts CLIENT_ENV; a test keeps the lists equal): nothing else is sent. */
static const char *const CLIENT_ENV[] = {
  "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_CODE_PLUGIN_CACHE_DIR", "CODEX_HOME", "HOME", "PATH", "SSH_AUTH_SOCK",
  "IRONTRELLIS_HOOK_CONFIG", "IRONTRELLIS_HOME", "IRONTRELLIS_WITNESS_POLICY", "IRONTRELLIS_CHALLENGE_PROFILE",
};

typedef struct { char *b; size_t n, cap; } buf;
static void put(buf *x, const char *s, size_t n) {
  if (x->n + n + 1 > x->cap) { x->cap = (x->n + n + 1) * 2; x->b = realloc(x->b, x->cap); if (!x->b) exit(2); }
  memcpy(x->b + x->n, s, n); x->n += n; x->b[x->n] = 0;
}
static void puts_(buf *x, const char *s) { put(x, s, strlen(s)); }
static void putj(buf *x, const char *s, size_t n) {
  put(x, "\"", 1);
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i]; char e[8];
    if (c == '"' || c == '\\') { e[0] = '\\'; e[1] = (char)c; put(x, e, 2); }
    else if (c < 0x20) { snprintf(e, sizeof e, "\\u%04x", c); put(x, e, 6); }
    else put(x, (const char *)&c, 1);
  }
  put(x, "\"", 1);
}
static void utf8(buf *o, unsigned u) {
  char e[4]; int n;
  if (u < 0x80) { e[0] = (char)u; n = 1; }
  else if (u < 0x800) { e[0] = (char)(0xC0 | (u >> 6)); e[1] = (char)(0x80 | (u & 63)); n = 2; }
  else if (u < 0x10000) { e[0] = (char)(0xE0 | (u >> 12)); e[1] = (char)(0x80 | ((u >> 6) & 63)); e[2] = (char)(0x80 | (u & 63)); n = 3; }
  else { e[0] = (char)(0xF0 | (u >> 18)); e[1] = (char)(0x80 | ((u >> 12) & 63)); e[2] = (char)(0x80 | ((u >> 6) & 63)); e[3] = (char)(0x80 | (u & 63)); n = 4; }
  put(o, e, (size_t)n);
}
/* One JSON string at p (as JSON.stringify writes it) into o; returns the position after it, or NULL. */
static const char *jstr(const char *p, buf *o) {
  if (*p++ != '"') return NULL;
  while (*p && *p != '"') {
    if (*p != '\\') { put(o, p, 1); p++; continue; }
    p++; char c = *p++;
    switch (c) {
      case '"': case '\\': case '/': put(o, &c, 1); break;
      case 'b': put(o, "\b", 1); break; case 'f': put(o, "\f", 1); break; case 'n': put(o, "\n", 1); break;
      case 'r': put(o, "\r", 1); break; case 't': put(o, "\t", 1); break;
      case 'u': {
        unsigned u, l; if (sscanf(p, "%4x", &u) != 1) return NULL; p += 4;
        if (u >= 0xD800 && u < 0xDC00 && p[0] == '\\' && p[1] == 'u' && sscanf(p + 2, "%4x", &l) == 1 && l >= 0xDC00 && l < 0xE000) { p += 6; u = 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00); }
        utf8(o, u); break;
      }
      default: return NULL;
    }
  }
  return *p == '"' ? p + 1 : NULL;
}
/* The daemon's own rule: the socket and its directory are this user's, nobody else can reach the directory, and every
 * directory above it (symlinks resolved) is this user's or root's and writable by nobody else unless root's and sticky. */
static int trusted(const char *path) {
  char d[PATH_MAX], real[PATH_MAX]; struct stat s, k; uid_t uid = getuid();
  if (strlen(path) >= sizeof d) return 0;
  strcpy(d, path);
  const char *dir = dirname(d);
  if (lstat(dir, &s) != 0 || !S_ISDIR(s.st_mode) || s.st_uid != uid || (s.st_mode & 077) != 0) return 0;
  if (lstat(path, &k) != 0 || !S_ISSOCK(k.st_mode) || k.st_uid != uid) return 0;
  if (realpath(dir, real) == NULL) return 0;
  for (;;) {
    char *slash = strrchr(real, '/');
    if (slash == NULL || (slash == real && real[1] == 0)) return 1;
    if (slash == real) slash[1] = 0; else *slash = 0;
    if (stat(real, &s) != 0) return 0;
    if (s.st_uid != uid && s.st_uid != 0) return 0;
    if ((s.st_mode & 022) != 0 && !((s.st_mode & S_ISVTX) != 0 && s.st_uid == 0)) return 0;
  }
}
/* The hook, with the same arguments and standard input. */
static int fallback(char **argv, const buf *in) {
  const char *hook = getenv("IRONTRELLISD_FALLBACK");
  if (hook == NULL || *hook == 0) {
    fprintf(stderr, "\nIronTrellis \xc2\xb7 DENY: the resident guard cannot answer this call and IRONTRELLISD_FALLBACK names no hook to run instead (DAEMON_UNAVAILABLE)\n");
    return 2;
  }
  int p[2]; if (pipe(p) != 0) return 2;
  pid_t pid = fork();
  if (pid < 0) return 2;
  if (pid == 0) { dup2(p[0], 0); close(p[0]); close(p[1]); execl(hook, hook, argv[1], argv[2], (char *)NULL); _exit(2); }
  close(p[0]); signal(SIGPIPE, SIG_IGN);
  for (size_t off = 0; off < in->n;) { ssize_t w = write(p[1], in->b + off, in->n - off); if (w <= 0) break; off += (size_t)w; }
  close(p[1]);
  int st; if (waitpid(pid, &st, 0) < 0) return 2;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 2;
}
int main(int argc, char **argv) {
  buf in = {0}; char tmp[65536]; ssize_t r;
  while ((r = read(0, tmp, sizeof tmp)) > 0) put(&in, tmp, (size_t)r);
  if (argc != 3) return fallback(argv, &in);
  char path[PATH_MAX]; const char *named = getenv("IRONTRELLISD_SOCKET"), *runtime = getenv("XDG_RUNTIME_DIR"), *home = getenv("IRONTRELLIS_HOME"), *user = getenv("HOME");
  if (named != NULL && *named != 0) snprintf(path, sizeof path, "%s", named);
  else if (runtime != NULL && runtime[0] == '/') snprintf(path, sizeof path, "%s/irontrellis/irontrellisd.sock", runtime);
  else if (home != NULL && *home != 0) snprintf(path, sizeof path, "%s/run/irontrellisd.sock", home);
  else if (user != NULL && *user != 0) snprintf(path, sizeof path, "%s/.irontrellis/run/irontrellisd.sock", user);
  else return fallback(argv, &in);
  if (!trusted(path)) return fallback(argv, &in);
  buf q = {0};
  puts_(&q, "{\"v\":1,\"protocol\":"); putj(&q, argv[1], strlen(argv[1]));
  puts_(&q, ",\"event\":"); putj(&q, argv[2], strlen(argv[2]));
  puts_(&q, ",\"stdin\":"); putj(&q, in.b == NULL ? "" : in.b, in.n);
  puts_(&q, ",\"env\":{"); int first = 1;
  for (size_t i = 0; i < sizeof CLIENT_ENV / sizeof CLIENT_ENV[0]; i++) {
    const char *v = getenv(CLIENT_ENV[i]); if (v == NULL) continue;
    if (!first) put(&q, ",", 1);
    first = 0;
    putj(&q, CLIENT_ENV[i], strlen(CLIENT_ENV[i])); put(&q, ":", 1); putj(&q, v, strlen(v));
  }
  char cwd[PATH_MAX]; if (!getcwd(cwd, sizeof cwd)) return fallback(argv, &in);
  puts_(&q, "},\"cwd\":"); putj(&q, cwd, strlen(cwd)); puts_(&q, "}\n");
  struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof a.sun_path) return fallback(argv, &in);
  strcpy(a.sun_path, path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return fallback(argv, &in);
  struct timeval limit = { 15, 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
  if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) return fallback(argv, &in);
  signal(SIGPIPE, SIG_IGN);
  for (size_t off = 0; off < q.n;) { ssize_t w = write(fd, q.b + off, q.n - off); if (w <= 0) return fallback(argv, &in); off += (size_t)w; }
  buf out = {0}; while ((r = read(fd, tmp, sizeof tmp)) > 0) put(&out, tmp, (size_t)r);
  close(fd);
  if (r < 0 || out.n == 0) return fallback(argv, &in);
  buf so = {0}, se = {0}; const char *p = out.b; long code;
  if (strncmp(p, "{\"stdout\":", 10) != 0 || !(p = jstr(p + 10, &so))) return fallback(argv, &in);
  if (strncmp(p, ",\"stderr\":", 10) != 0 || !(p = jstr(p + 10, &se))) return fallback(argv, &in);
  if (strncmp(p, ",\"exitCode\":", 12) != 0 || sscanf(p + 12, "%ld", &code) != 1) return fallback(argv, &in);
  if (so.n) fwrite(so.b, 1, so.n, stdout);
  if (se.n) fwrite(se.b, 1, se.n, stderr);
  return (int)code;
}
