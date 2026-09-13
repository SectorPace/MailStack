/**
 * Dovecot auth-client protocol over the auth-client unix socket.
 *
 * The previous login path spawned `doveadm auth test <user> <password>`, which
 * put the mailbox password in the process argv. Anything able to read
 * /proc/<pid>/cmdline during the call -- other unprivileged users, container
 * neighbours with a shared /proc, `ps` sampling -- could lift it. The password
 * now only ever travels inside the socket payload, which is protected by the
 * socket's filesystem permissions (mode 0660, owner mailstack-webmail/dovecot).
 *
 * Protocol reference (Dovecot auth protocol, client side):
 *   server -> "VERSION\t1\t1", "SPID\t<pid>"
 *   client -> "VERSION\t1\t1", "CPID\t<pid>",
 *             "AUTH\t<id>\tPLAIN\tservice=<service>\tresp=<base64 \0user\0pass>"
 *   server -> "OK\t<id>\tuser=<user>" | "FAIL\t<id>" | "NOTFOUND\t<id>"
 *
 * Fail-closed by construction: any socket error, timeout, malformed line or
 * protocol surprise resolves to `false`, never to a thrown exception that
 * could be distinguished from "wrong password" at the HTTP layer.
 */
import net from 'net';

export const DOVECOT_AUTH_SOCKET = String(
  process.env.DOVECOT_AUTH_SOCKET || '/var/run/dovecot/auth-client',
).trim();

const MAX_HANDSHAKE_BYTES = 65536;

export function dovecotAuthTest(user, password, options = {}) {
  const socketPath = options.socketPath || DOVECOT_AUTH_SOCKET;
  const service = /^[a-z][a-z0-9-]{0,31}$/.test(String(options.service || 'webmail'))
    ? String(options.service || 'webmail')
    : 'webmail';
  const timeoutMs = Math.max(1000, Number(options.timeoutMs) || 10000);
  // unixUser is regex-validated upstream (^[a-z_][a-z0-9_-]{0,31}$); guard here
  // as well so a tab/newline can never smuggle an extra protocol line.
  const safeUser = String(user || '');
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(safeUser)) return Promise.resolve(false);

  return new Promise((resolve) => {
    let settled = false;
    let sock = null;
    const done = (ok) => {
      if (settled) return;
      settled = true;
      try { if (sock) sock.destroy(); } catch { /* already closed */ }
      resolve(ok === true);
    };

    try {
      sock = net.createConnection(socketPath);
    } catch {
      return done(false);
    }

    let buffer = '';
    let handshaken = false;
    let requestId = 0;
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once('error', () => done(false));
    sock.once('close', () => done(false));
    sock.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      if (buffer.length > MAX_HANDSHAKE_BYTES) return done(false);
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!handshaken) {
          if (!line.startsWith('VERSION\t')) continue; // SPID etc.
          const major = Number(line.split('\t')[1]);
          if (major !== 1) return done(false);
          try {
            const resp = Buffer.from(`\x00${safeUser}\x00${String(password)}`, 'utf8').toString('base64');
            requestId = 1;
            sock.write(
              `VERSION\t1\t1\nCPID\t${process.pid}\n` +
              `AUTH\t${requestId}\tPLAIN\tservice=${service}\tresp=${resp}\n`,
            );
            handshaken = true;
          } catch {
            return done(false);
          }
          continue;
        }
        const parts = line.split('\t');
        if (Number(parts[1]) !== requestId) continue; // not our request
        if (parts[0] === 'OK') return done(true);
        if (parts[0] === 'FAIL' || parts[0] === 'NOTFOUND') return done(false);
        // CONT (continued auth) is not expected for one-shot PLAIN; ignore.
      }
    });
  });
}
