export interface Env {
  CONFIG_KV: KVNamespace;   // 存储配置
  LOG_KV: KVNamespace;      // 存储操作日志
  API_TOKEN: string;        // 管理员 Token（用于生成/查看 API 密钥）
}

// 工具：生成随机 Token
function generateToken(): string {
  return 'kv_' + crypto.randomUUID().replace(/-/g, '');
}

// 记录操作日志
async function logOperation(env: Env, operation: string, key: string, result: string, details?: any) {
  const logId = Date.now().toString() + '_' + crypto.randomUUID().slice(0, 8);
  const logEntry = {
    id: logId,
    timestamp: new Date().toISOString(),
    operation,   // "create", "update", "delete", "get"
    key,
    result,
    details: details ? JSON.stringify(details) : '',
  };
  await env.LOG_KV.put(logId, JSON.stringify(logEntry));
  // 可选：保留最近 1000 条日志，简单轮转（略）
}

// 验证前端请求的 API Key（用户自行生成的 Token）
function validateUserToken(request: Request, env: Env): boolean {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  // 从 KV 中读取有效的用户 Token 列表（简单实现：存储一个名为 "valid_tokens" 的 JSON 数组）
  // 为了简化，允许使用环境变量 API_TOKEN 作为唯一有效 Token
  // 但为了前端管理功能，我们可以存储多个 Token。这里先实现单 Token 模式，通过 /api/auth/token 管理
  // 实际使用：前端保存 Token，Worker 验证它是否等于 env.API_TOKEN 或存储在 KV 中的 tokens
  if (token === env.API_TOKEN) return true;
  // 可选：从 KV 读取允许的 tokens 列表（高级）
  return false;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    // ========== 公开端点：获取当前 API Token（仅用于初始化，需管理员验证） ==========
    // 为了安全，仅允许从 localhost 或特定来源访问，这里简单加一个内部头
    if (path === '/api/auth/token' && request.method === 'GET') {
      const internalKey = request.headers.get('X-Admin-Key');
      if (internalKey !== env.API_TOKEN) {
        return jsonResponse({ error: 'Forbidden' }, 403);
      }
      // 获取当前存储的用户 Token（如果没有，生成一个并存储）
      let userToken = await env.CONFIG_KV.get('__user_token');
      if (!userToken) {
        userToken = generateToken();
        await env.CONFIG_KV.put('__user_token', userToken);
      }
      return jsonResponse({ token: userToken });
    }

    // ========== 需要用户 Token 验证的端点 ==========
    if (!validateUserToken(request, env)) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    // ------------------- 配置管理 API -------------------
    if (path === '/api/config/list' && request.method === 'GET') {
      const keys = await env.CONFIG_KV.list();
      const items: Record<string, any> = {};
      for (const key of keys.keys) {
        if (key.name.startsWith('__')) continue; // 跳过内部 key
        const value = await env.CONFIG_KV.get(key.name);
        if (value) {
          items[key.name] = JSON.parse(value);
        }
      }
      return jsonResponse({ success: true, data: items });
    }

    if (path.startsWith('/api/config/') && !path.startsWith('/api/config/list')) {
      const key = path.replace('/api/config/', '');
      if (!key || key.startsWith('__')) {
        return jsonResponse({ error: 'Invalid key' }, 400);
      }

      switch (request.method) {
        case 'GET':
          const val = await env.CONFIG_KV.get(key);
          await logOperation(env, 'get', key, 'success');
          return jsonResponse({ key, value: val ? JSON.parse(val) : null });

        case 'POST':
          const body = await request.json() as { value: any };
          // 判断是创建还是更新
          const exists = await env.CONFIG_KV.get(key);
          const operation = exists ? 'update' : 'create';
          await env.CONFIG_KV.put(key, JSON.stringify(body.value));
          await logOperation(env, operation, key, 'success', { value: body.value });
          return jsonResponse({ success: true, key, value: body.value });

        case 'DELETE':
          await env.CONFIG_KV.delete(key);
          await logOperation(env, 'delete', key, 'success');
          return jsonResponse({ success: true, key });

        default:
          return new Response('Method Not Allowed', { status: 405 });
      }
    }

    // ------------------- 操作日志 API -------------------
    if (path === '/api/logs/list' && request.method === 'GET') {
      const logs = await env.LOG_KV.list({ limit: 200 });
      const items = [];
      for (const log of logs.keys) {
        const raw = await env.LOG_KV.get(log.name);
        if (raw) items.push(JSON.parse(raw));
      }
      // 按时间倒序
      items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      return jsonResponse({ success: true, logs: items });
    }

    // ------------------- 管理自己的 API Token -------------------
    if (path === '/api/user/token' && request.method === 'POST') {
      // 生成新 token，替换旧的
      const newToken = generateToken();
      await env.CONFIG_KV.put('__user_token', newToken);
      await logOperation(env, 'rotate_token', '__user_token', 'success');
      return jsonResponse({ token: newToken });
    }

    return new Response('Not Found', { status: 404 });
  },
};

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(data: any, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}