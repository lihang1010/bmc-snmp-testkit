const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../src/snmp_test/service/templates/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function dashboard() {
  let now = 0, nextId = 0;
  const timers = new Map(), elements = new Map(), calls = [];
  const settings = { running: true, empty: false, delay: 0, sessionStatus: 200, jobsStatus: 200, hang: false };
  const active = new Map(), peak = new Map();
  const location = { href: '/' };
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value: '', textContent: '', innerHTML: '', style: {}, checked: false,
      listeners: {}, disabled: false,
      classList: { add() {}, remove() {}, toggle() {}, contains() { return true; } },
      addEventListener(event, callback) { this.listeners[event] = callback; },
      setAttribute() {}, focus() {},
    });
    return elements.get(id);
  };
  function schedule(callback, delay, interval = 0) {
    const id = ++nextId;
    timers.set(id, { callback, at: now + delay, interval });
    return id;
  }
  const bodies = {
    '/api/session': () => ({ user: 'test@example.com' }),
    '/api/config': () => ({ workers: 2, current_jobs: [], queue_length: 0, mib_count: 0, job_count: 1 }),
    '/api/mibs': () => ({ mibs: [] }),
    '/api/jobs': () => ({ jobs: settings.empty ? [] : [{
      job_id: 'test-job', status: settings.running ? 'running' : 'done', mode: 'mock', version: 'v2c',
      limit: 0, progress: { done: 750, total: 2063, passed: 632, failed: 2, unsupported: 116 },
      summary: { passed: 1748, total: 2063, effective_pass_rate: 99.37 },
    }] }),
  };
  function fetch(url, options = {}) {
    calls.push({ url, at: now, method: options.method || 'GET' });
    active.set(url, (active.get(url) || 0) + 1);
    peak.set(url, Math.max(peak.get(url) || 0, active.get(url)));
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = () => {
        if (settled) return false;
        settled = true;
        active.set(url, active.get(url) - 1);
        return true;
      };
      if (options.signal) options.signal.addEventListener('abort', () => {
        if (finish()) reject(new DOMException('Aborted', 'AbortError'));
      }, { once: true });
      if (settings.hang && url === '/api/jobs' && !options.method) return;
      const reply = () => {
        if (!finish()) return;
        const status = url === '/api/session' ? settings.sessionStatus :
          url === '/api/jobs' ? settings.jobsStatus : 200;
        resolve({ ok: status === 200, status, json: async () => status === 200
          ? (options.method === 'POST' ? { job: { job_id: 'test-job' } } : bodies[url]())
          : { detail: 'test error' } });
      };
      if (settings.delay) schedule(reply, settings.delay);
      else reply();
    });
  }
  const document = {
    getElementById: element, addEventListener() {}, querySelectorAll: () => [],
  };
  const context = vm.createContext({
    document, location, fetch, AbortController, DOMException, URLSearchParams, console,
    setTimeout: (cb, ms) => schedule(cb, ms), clearTimeout: id => timers.delete(id),
    setInterval: (cb, ms) => schedule(cb, ms, ms), clearInterval: id => timers.delete(id),
  });
  vm.runInContext(script, context);
  const settle = () => new Promise(resolve => setImmediate(resolve));
  async function advance(ms) {
    await settle();
    const end = now + ms;
    while (true) {
      const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (!next || next[1].at > end) break;
      const [id, timer] = next;
      now = timer.at;
      timers.delete(id);
      if (timer.interval) timers.set(id, { ...timer, at: now + timer.interval });
      timer.callback();
      await settle();
    }
    now = end;
    await settle();
  }
  async function submit() {
    element('version').value = 'v2c';
    element('community').value = 'test-community';
    element('mibId').value = '0'.repeat(16);
    element('host').value = '192.0.2.1';
    element('modules').value = '';
    element('runAll').checked = true;
    element('submitBtn').listeners.click();
    await settle();
  }
  return { settings, calls, peak, location, element, advance, submit };
}

test('long tasks keep one polling chain rather than accumulating timers', async () => {
  const page = dashboard();
  await page.advance(10 * 60 * 1000);
  const polls = page.calls.filter(c => c.url === '/api/jobs');
  assert.equal(polls.length, 301);
  for (let minute = 0; minute < 10; minute++) {
    assert.equal(polls.filter(c => c.at >= minute * 60000 && c.at < (minute + 1) * 60000).length, 30);
  }
});

test('slow responses never overlap polling rounds', async () => {
  const page = dashboard();
  page.settings.delay = 3500;
  await page.advance(60000);
  assert.equal(page.peak.get('/api/jobs'), 1);
  assert.equal(page.peak.get('/api/session'), 1);
});

test('submitting during a refresh does not start another polling chain', async () => {
  const page = dashboard();
  page.settings.delay = 500;
  await page.advance(1000);
  await page.submit();
  await page.advance(100);
  await page.submit();
  await page.advance(60000);
  assert.equal(page.peak.get('/api/session'), 1);
  const gets = page.calls.filter(c => c.url === '/api/jobs' && c.method === 'GET');
  assert.ok(gets.length <= 23, `unexpected polling count: ${gets.length}`);
});

for (const empty of [false, true]) {
  test(`${empty ? 'empty' : 'finished'} jobs resume the idle polling interval`, async () => {
    const page = dashboard();
    await page.advance(4000);
    page.settings.running = false;
    page.settings.empty = empty;
    await page.advance(2000);
    const before = page.calls.length;
    await page.advance(7999);
    assert.equal(page.calls.length, before);
    await page.advance(1);
    assert.equal(page.calls.length, before + 4);
  });
}

test('a failed jobs request preserves the current display and polling recovers', async () => {
  const page = dashboard();
  await page.advance(0);
  const before = page.element('jobBody').innerHTML;
  page.settings.jobsStatus = 500;
  await page.advance(2000);
  assert.equal(page.element('jobBody').innerHTML, before);
  assert.equal(page.location.href, '/');
  page.settings.jobsStatus = 200;
  page.settings.running = false;
  await page.advance(8000);
  assert.match(page.element('jobBody').innerHTML, /1748\/2063/);
});

test('network errors do not redirect a valid session to login', async () => {
  const page = dashboard();
  await page.advance(0);
  page.settings.sessionStatus = 503;
  await page.advance(2000);
  assert.equal(page.location.href, '/');
  page.settings.sessionStatus = 200;
  await page.advance(8000);
  assert.match(page.element('jobBody').innerHTML, /750\/2063/);
});

test('expired sessions redirect without leaving a polling chain', async () => {
  const page = dashboard();
  await page.advance(0);
  page.settings.sessionStatus = 401;
  await page.advance(2000);
  assert.equal(page.location.href, '/login');
  const before = page.calls.length;
  await page.advance(30000);
  assert.equal(page.calls.length, before);
});

test('hung polling requests time out, then retry without accumulating requests', async () => {
  const page = dashboard();
  await page.advance(0);
  page.settings.hang = true;
  await page.advance(12000);
  page.settings.hang = false;
  page.settings.running = false;
  await page.advance(8000);
  assert.match(page.element('jobBody').innerHTML, /1748\/2063/);
  assert.equal(page.peak.get('/api/jobs'), 1);
});
