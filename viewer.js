(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const base = new URL('.', location.href);
  const report = 'reports/Сводный_отчет_по_филиалам.xlsx';
  let key = null, manifest = null, generation = 0;
  const bridgeId = crypto.randomUUID();
  const aad = new TextEncoder().encode('toir-site-v1');

  async function get(url, fresh = false) {
    const result = await fetch(url, { cache: fresh ? 'no-store' : 'default', credentials: 'omit' });
    if (!result.ok) throw new Error('network');
    return result;
  }

  async function decrypt(blobName, decryptionKey) {
    if (!/^[a-f0-9]{64}\.bin$/.test(blobName)) throw new Error('format');
    const data = new Uint8Array(await (await get(new URL(blobName, base))).arrayBuffer());
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: aad, tagLength: 128 }, decryptionKey, data.slice(12));
    return new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  }

  async function navigate(path) {
    if (!key || !manifest?.files[path]) throw new Error('file');
    const ownGeneration = ++generation;
    $('status').textContent = 'Открываю…';
    const entry = manifest.files[path], bytes = await decrypt(entry.blob, key);
    if (ownGeneration !== generation || !key) return;
    if (entry.type !== 'text/html') {
      const url = URL.createObjectURL(new Blob([bytes], { type: entry.type }));
      const link = document.createElement('a');
      link.href = url; link.download = path.split('/').at(-1);
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      $('status').textContent = 'Отчёт передан для скачивания.';
      return;
    }
    const doc = new DOMParser().parseFromString(new TextDecoder().decode(bytes), 'text/html');
    doc.querySelectorAll('meta[http-equiv="refresh"],base').forEach(node => node.remove());
    const script = doc.createElement('script');
    script.textContent = `document.addEventListener('click',function(event){
      var anchor=event.target.closest&&event.target.closest('a[href]');if(!anchor)return;
      var href=anchor.getAttribute('href');if(!href||href[0]==='#')return;
      var dest;try{dest=new URL(href,'https://toir.invalid/'+${JSON.stringify(path)});}catch{return;}
      if(dest.origin!=='https://toir.invalid')return;
      event.preventDefault();parent.postMessage({bridge:${JSON.stringify(bridgeId)},path:decodeURIComponent(dest.pathname.slice(1))},'*');
    },true);`;
    doc.head.prepend(script);
    $('content').srcdoc = '<!doctype html>' + doc.documentElement.outerHTML;
    $('status').textContent = path.split('/').at(-1).replace(/\.html$/, '');
  }

  async function open(path) {
    try { await navigate(path); }
    catch { $('status').textContent = 'Не удалось открыть файл. Проверьте соединение и обновите страницу.'; }
  }

  $('login').addEventListener('submit', async event => {
    event.preventDefault(); $('message').textContent = ''; $('enter').disabled = true;
    try {
      if (!crypto.subtle || !window.DecompressionStream) throw new Error('browser');
      const pointer = await (await get(new URL('site.json', base), true)).json();
      if (pointer.version !== 1 || pointer.iterations !== 600000 || typeof pointer.salt !== 'string') throw new Error('format');
      const salt = Uint8Array.from(atob(pointer.salt), char => char.charCodeAt(0));
      if (salt.length !== 32) throw new Error('format');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode($('password').value), 'PBKDF2', false, ['deriveKey']);
      const candidate = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: pointer.iterations, hash: 'SHA-256' }, material,
        { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      const catalog = JSON.parse(new TextDecoder().decode(await decrypt(pointer.manifest, candidate)));
      if (catalog.version !== 1 || !catalog.files?.['html/index.html'] || !catalog.files?.[report]) throw new Error('format');
      key = candidate; manifest = catalog; $('password').value = '';
      $('entry').hidden = true; $('app').hidden = false;
      await open('html/index.html');
    } catch (error) {
      $('message').textContent = error.message === 'browser' ? 'Откройте сайт в современной версии браузера по HTTPS.' :
        error.name === 'OperationError' ? 'Неверный пароль.' : 'Сайт пока не готов или нет соединения. Попробуйте позже.';
    } finally { $('enter').disabled = false; }
  });
  $('home').onclick = () => open('html/index.html');
  $('summary').onclick = () => open('html/summary_report.html');
  $('excel').onclick = () => open(report);
  $('logout').onclick = () => {
    key = null; manifest = null; generation++; $('content').srcdoc = ''; $('status').textContent = '';
    $('app').hidden = true; $('entry').hidden = false; $('password').focus();
  };
  window.addEventListener('message', event => {
    if (event.source === $('content').contentWindow && event.data?.bridge === bridgeId && manifest?.files[event.data.path]) open(event.data.path);
  });
})();
