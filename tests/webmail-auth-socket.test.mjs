/**
 * Behavioural cover for the webmail login password path.
 *
 * The old implementation ran `doveadm auth test <user> <password>`; the
 * password sat in the child process argv, readable from /proc/<pid>/cmdline
 * by any local user for the lifetime of the call. Login now speaks the
 * Dovecot auth-client protocol over the auth-client unix socket, so the
 * password only exists inside the socket payload.
 *
 * These tests stand up a fake Dovecot auth socket and pin three properties:
 *   1. a correct password authenticates, a wrong one does not;
 *   2. the wire format is the documented protocol (base64 of \0user\0pass),
 *      and the cleartext password never appears in any frame;
 *   3. no child process is spawned for authentication at all -- with no
 *      doveadm invocation there is no argv that could contain the password.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { dovecotAuthTest } from '../webmail/dovecot-auth.mjs';

function fakeDovecotAuth(socketPath, { expectedUser, expectedPass, frames = [] }) {
  const server = net.createServer((conn) => {
    conn.write('VERSION\t1\t1\nSPID\t4242\n');
    let buffer = '';
    conn.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.startsWith('AUTH\t')) {
          frames.push(line);
          const resp = line.split('\t').find((p) => p.startsWith('resp='));
          const decoded = Buffer.from(resp.slice(5), 'base64').toString('utf8');
          const ok = decoded === `\x00${expectedUser}\x00${expectedPass}`;
          conn.write(ok ? 'OK\t1\tuser=' + expectedUser + '\n' : 'FAIL\t1\n');
        }
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(server));
  });
}

function tempSocketPath(t) {
  // Windows has no unix-domain socket files; Node maps pipe paths onto named
  // pipes, which must use the \\?\pipe\ namespace there.
  const name = `ms-dovecot-auth-${process.pid}-${Math.floor(Math.random() * 1e6)}`;
  const p = process.platform === 'win32'
    ? `\\\\?\\pipe\\${name}`
    : path.join(os.tmpdir(), `${name}.sock`);
  t.after(() => { try { fs.unlinkSync(p); } catch { /* windows named pipes vanish with the server */ } });
  return p;
}

const PASSWORD = 'Sup3r-Secret!Mailbox#Password';

test('correct credentials authenticate over the auth-client socket', async (t) => {
  const sock = tempSocketPath(t);
  const frames = [];
  const server = await fakeDovecotAuth(sock, { expectedUser: 'alice', expectedPass: PASSWORD, frames });
  t.after(() => server.close());
  const ok = await dovecotAuthTest('alice', PASSWORD, { socketPath: sock, timeoutMs: 3000 });
  assert.equal(ok, true);
  const authLine = frames.find((f) => f.startsWith('AUTH\t'));
  assert.ok(authLine, 'an AUTH frame must have been sent');
  assert.match(authLine, /^AUTH\t1\tPLAIN\tservice=webmail\tresp=/);
  assert.ok(!authLine.includes(PASSWORD), 'cleartext password must not appear in any protocol frame');
});

test('wrong credentials are rejected and fail closed', async (t) => {
  const sock = tempSocketPath(t);
  const server = await fakeDovecotAuth(sock, { expectedUser: 'alice', expectedPass: PASSWORD });
  t.after(() => server.close());
  assert.equal(await dovecotAuthTest('alice', 'not-the-password', { socketPath: sock, timeoutMs: 3000 }), false);
});

test('a missing socket fails closed instead of throwing', async () => {
  const missing = path.join(os.tmpdir(), `ms-dovecot-auth-absent-${process.pid}.sock`);
  assert.equal(await dovecotAuthTest('alice', PASSWORD, { socketPath: missing, timeoutMs: 1500 }), false);
});

test('usernames that could smuggle protocol lines are refused locally', async (t) => {
  const sock = tempSocketPath(t);
  const frames = [];
  const server = await fakeDovecotAuth(sock, { expectedUser: 'alice', expectedPass: PASSWORD, frames });
  t.after(() => server.close());
  for (const evil of ['ali ce', 'alice\tresp=', 'alice\nFAIL', '../root', 'ALICE']) {
    assert.equal(await dovecotAuthTest(evil, PASSWORD, { socketPath: sock, timeoutMs: 1000 }), false, `${evil} must be refused`);
  }
  assert.equal(frames.length, 0, 'refused usernames must never reach the socket');
});

test('authentication spawns no child process, so no argv can leak the password', () => {
  const moduleSource = fs.readFileSync(new URL('../webmail/dovecot-auth.mjs', import.meta.url), 'utf8');
  assert.ok(!moduleSource.includes('child_process'), 'dovecot-auth.mjs must not spawn processes');
  const serverSource = fs.readFileSync(new URL('../webmail/server.mjs', import.meta.url), 'utf8');
  assert.ok(!/doveadm[\s\S]{0,40}auth[\s\S]{0,10}test/.test(serverSource), 'webmail must not invoke `doveadm auth test`');
});
