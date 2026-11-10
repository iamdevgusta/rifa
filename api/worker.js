// API da rifa: um arquivo só.
// GET  /state -> devolve o JSON salvo (ou null)
// PUT  /state -> grava o JSON inteiro (exige o cabeçalho X-Senha igual ao segredo SENHA)
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Senha',
};
const json = (body, status = 200) =>
  new Response(body, { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (new URL(req.url).pathname !== '/state') return json('{"erro":"rota inexistente"}', 404);

    if (req.method === 'GET') return json((await env.RIFA.get('state')) || 'null');

    if (req.method === 'PUT') {
      if (!env.SENHA || req.headers.get('X-Senha') !== env.SENHA) return json('{"erro":"senha incorreta"}', 401);
      const body = await req.text();
      if (body.length > 1_000_000) return json('{"erro":"muito grande"}', 413);
      try { JSON.parse(body); } catch { return json('{"erro":"json inválido"}', 400); }
      const prev = await env.RIFA.get('state');
      if (prev) await env.RIFA.put('state-anterior', prev); // backup da última versão
      await env.RIFA.put('state', body);
      return json('{"ok":true}');
    }
    return json('{"erro":"método não permitido"}', 405);
  },
};
