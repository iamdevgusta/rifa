const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};
const TOKEN_DIAS = 30;
const MAX_ARQUIVO = 5 * 1024 * 1024;
const enc = new TextEncoder();

const resp = (body, status = 200, type = 'application/json') =>
  new Response(body, { status, headers: { ...CORS, 'Content-Type': type, 'Cache-Control': 'no-store' } });
const erro = (msg, status) => resp(JSON.stringify({ erro: msg }), status);

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sha256 = async txt => hex(await crypto.subtle.digest('SHA-256', enc.encode(txt)));
function iguais(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function assinar(env, payload) {
  const key = await crypto.subtle.importKey('raw', enc.encode(env.TOKEN_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(payload)));
}
async function tokenValido(env, req) {
  const t = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const [exp, sig] = t.split('.');
  if (!exp || !sig || !(Number(exp) > Date.now())) return false;
  return iguais(sig, await assinar(env, exp));
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (!env.SENHA_HASH || !env.TOKEN_KEY) return erro('API sem configuração', 500);
    const path = new URL(req.url).pathname;

    if (path === '/login' && req.method === 'POST') {
      let senha = '';
      try { senha = String((await req.json()).senha || ''); } catch {}
      if (!iguais(await sha256('rifa:' + senha), env.SENHA_HASH)) {
        await new Promise(r => setTimeout(r, 800));
        return erro('senha incorreta', 401);
      }
      const exp = String(Date.now() + TOKEN_DIAS * 864e5);
      return resp(JSON.stringify({ token: `${exp}.${await assinar(env, exp)}` }));
    }

    if (!(await tokenValido(env, req))) return erro('não autorizado', 401);

    if (path === '/state') {
      if (req.method === 'GET') return resp((await env.RIFA.get('state')) || 'null');
      if (req.method === 'PUT') {
        const body = await req.text();
        if (body.length > 1_000_000) return erro('muito grande', 413);
        try { JSON.parse(body); } catch { return erro('json inválido', 400); }
        const prev = await env.RIFA.get('state');
        if (prev) await env.RIFA.put('state-anterior', prev);
        await env.RIFA.put('state', body);
        return resp('{"ok":true}');
      }
    }

    if (path === '/comprovantes' && req.method === 'POST') {
      const type = (req.headers.get('Content-Type') || '').split(';')[0];
      if (!/^image\/(jpeg|png|webp)$|^application\/pdf$/.test(type)) return erro('tipo de arquivo não aceito', 415);
      const buf = await req.arrayBuffer();
      if (!buf.byteLength || buf.byteLength > MAX_ARQUIVO) return erro('arquivo vazio ou maior que 5 MB', 413);
      const id = crypto.randomUUID();
      await env.RIFA.put('comp:' + id, buf, { metadata: { type } });
      return resp(JSON.stringify({ id }));
    }

    const m = path.match(/^\/comprovantes\/([0-9a-f-]{36})$/);
    if (m) {
      if (req.method === 'GET') {
        const { value, metadata } = await env.RIFA.getWithMetadata('comp:' + m[1], 'arrayBuffer');
        if (!value) return erro('não encontrado', 404);
        return resp(value, 200, (metadata && metadata.type) || 'application/octet-stream');
      }
      if (req.method === 'DELETE') {
        await env.RIFA.delete('comp:' + m[1]);
        return resp('{"ok":true}');
      }
    }

    return erro('rota inexistente', 404);
  },
};
