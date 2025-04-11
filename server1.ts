import { serve } from "https://deno.land/std@0.140.0/http/server.ts";

const PORT = Deno.env.get("PORT") || 8000;

// API映射配置 - 包含所有原始支持的API
const apiMapping = {
  '/discord': 'https://discord.com/api',
  '/telegram': 'https://api.telegram.org',
  '/openai': 'https://api.openai.com',
  '/claude': 'https://api.anthropic.com',
  '/gemini': 'https://generativelanguage.googleapis.com',
  '/meta': 'https://www.meta.ai/api',
  '/groq': 'https://api.groq.com/openai',
  '/xai': 'https://api.x.ai',
  '/cohere': 'https://api.cohere.ai',
  '/huggingface': 'https://api-inference.huggingface.co',
  '/together': 'https://api.together.xyz',
  '/novita': 'https://api.novita.ai',
  '/portkey': 'https://api.portkey.ai',
  '/fireworks': 'https://api.fireworks.ai',
  '/github': 'https://api.githubcopilot.com',
  '/openrouter': 'https://openrouter.ai/api'
};

// 允许的请求头 - 扩展了重要头信息
const allowedHeaders = [
  // 基本HTTP头
  'accept', 
  'content-type',
  'authorization',
  
  // API密钥头
  'api-key',
  'x-api-key',
  
  // GitHub Copilot头
  'copilot-session-id',
  'copilot-trace-id',
  'github-token',
  'x-auth-token',
  'x-github-api-version',
  'x-github-enterprise-host',
  
  // WebSocket相关头
  'sec-websocket-protocol',
  'sec-websocket-extensions',
  
  // 自定义头和其他API常用头
  'x-requested-with',
  'anthropic-version',
  'anthropic-beta',
  'openai-organization',
  'openai-beta',
  
  // 缓存控制头
  'cache-control',
  'if-none-match',
  'if-modified-since'
];

// 主服务器函数
serve(async (request) => {
  const url = new URL(request.url);
  const pathname = url.pathname;
  
  console.log(`收到请求: ${request.method} ${pathname}`);
  
  // 处理CORS预检请求
  if (request.method === 'OPTIONS') {
    return handleCors();
  }
  
  // 处理基本路由
  if (pathname === '/' || pathname === '/index.html') {
    return new Response('API Proxy Service is running!', {
      status: 200,
      headers: { 
        'Content-Type': 'text/html',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  if (pathname === '/health' || pathname === '/healthz') {
    return new Response(JSON.stringify({ status: 'ok' }), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  if (pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /', {
      status: 200,
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  // 查找匹配的API前缀
  let matchedPrefix = null;
  let restPath = null;
  
  for (const prefix in apiMapping) {
    if (pathname.startsWith(prefix)) {
      matchedPrefix = prefix;
      restPath = pathname.slice(prefix.length);
      break;
    }
  }
  
  // 如果找到匹配的API前缀，代理请求
  if (matchedPrefix) {
    return await proxyRequest(request, apiMapping[matchedPrefix], restPath);
  }
  
  // 找不到匹配的路由，返回404
  return new Response('Not Found', { 
    status: 404,
    headers: {
      'Content-Type': 'text/plain',
      'Access-Control-Allow-Origin': '*'
    }
  });
}, { port: Number(PORT) });

// 处理CORS预检请求
function handleCors() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': allowedHeaders.join(', '),
      'Access-Control-Max-Age': '86400'
    }
  });
}

// 代理请求到目标API
async function proxyRequest(request, targetBase, path) {
  try {
    const url = new URL(request.url);
    const targetUrl = `${targetBase}${path}${url.search}`;
    
    console.log(`代理请求至: ${targetBase}${path}`);
    console.log(`完整目标URL: ${targetUrl}`);
    console.log(`请求方法: ${request.method}`);
    
    // 处理WebSocket请求
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      console.log(`处理WebSocket请求: ${targetUrl}`);
      return handleWebSocketRequest(request, targetUrl);
    }
    
    // 创建新的Headers对象，复制原始请求头
    const headers = new Headers();
    for (const [key, value] of request.headers.entries()) {
      // 排除特定的头信息，这些头应该由fetch自动设置
      if (!['host', 'connection', 'content-length'].includes(key.toLowerCase())) {
        headers.set(key, value);
        console.log(`转发请求头: ${key}`);
      }
    }
    
    // 确保Content-Type头正确设置（对于POST请求）
    if (!headers.has('Content-Type') && request.method === 'POST') {
      headers.set('Content-Type', 'application/json');
      console.log('添加默认Content-Type: application/json');
    }
    
    // 创建fetch选项
    const fetchOptions = {
      method: request.method,
      headers: headers,
      redirect: 'follow',
    };
    
    // 对于非GET/HEAD请求，添加请求体
    if (!['GET', 'HEAD'].includes(request.method)) {
      try {
        // 克隆请求体并读取为文本
        const clonedRequest = request.clone();
        const bodyText = await clonedRequest.text();
        
        if (bodyText) {
          console.log(`请求体预览: ${bodyText.substring(0, 100)}${bodyText.length > 100 ? '...' : ''}`);
          fetchOptions.body = bodyText;
        }
      } catch (bodyError) {
        console.error(`读取请求体出错: ${bodyError}`);
        // 即使读取失败，也尝试继续处理请求
        fetchOptions.body = request.body;
      }
    }
    
    // 发送请求到目标API
    console.log(`发送请求到: ${targetUrl}`);
    const response = await fetch(targetUrl, fetchOptions);
    
    console.log(`API响应: ${response.status} ${response.statusText}`);
    
    // 如果响应不成功，记录详情
    if (!response.ok) {
      try {
        const errorText = await response.clone().text();
        console.error(`API错误响应: ${errorText.substring(0, 500)}${errorText.length > 500 ? '...' : ''}`);
      } catch (e) {
        console.error(`无法读取错误响应正文: ${e}`);
      }
    }
    
    // 复制所有响应头
    const responseHeaders = new Headers();
    for (const [key, value] of response.headers.entries()) {
      responseHeaders.set(key, value);
    }
    
    // 添加CORS和安全头
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('X-Content-Type-Options', 'nosniff');
    responseHeaders.set('X-Frame-Options', 'DENY');
    responseHeaders.set('Referrer-Policy', 'no-referrer');
    
    // 返回响应给客户端
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    console.error(`代理请求处理错误: ${error.stack || error}`);
    
    return new Response(JSON.stringify({ 
      error: 'Proxy Error', 
      message: error.message,
      stack: Deno.env.get("DEBUG") === "true" ? error.stack : undefined
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// 处理WebSocket请求
async function handleWebSocketRequest(request, targetUrl) {
  try {
    // 将HTTP URL转换为WebSocket URL
    const wsTargetUrl = targetUrl.replace(/^http/i, 'ws');
    console.log(`WebSocket连接目标: ${wsTargetUrl}`);
    
    // 升级HTTP连接为WebSocket
    const { socket: clientSocket, response } = Deno.upgradeWebSocket(request);
    
    // 提取需要转发的头信息
    const headers = {};
    for (const [key, value] of request.headers.entries()) {
      if (allowedHeaders.includes(key.toLowerCase())) {
        headers[key] = value;
      }
    }
    
    // 连接到目标WebSocket
    console.log(`正在连接到WebSocket服务器...`);
    const serverSocket = new WebSocket(wsTargetUrl, [], { headers });
    
    // 客户端->服务器
    clientSocket.onmessage = (event) => {
      if (serverSocket.readyState === WebSocket.OPEN) {
        console.log(`WebSocket: 客户端 -> 服务器`);
        serverSocket.send(event.data);
      }
    };
    
    // 服务器->客户端
    serverSocket.onmessage = (event) => {
      if (clientSocket.readyState === WebSocket.OPEN) {
        console.log(`WebSocket: 服务器 -> 客户端`);
        clientSocket.send(event.data);
      }
    };
    
    // 连接打开处理
    serverSocket.onopen = () => {
      console.log('WebSocket: 服务器连接已打开');
    };
    
    clientSocket.onopen = () => {
      console.log('WebSocket: 客户端连接已打开');
    };
    
    // 错误处理
    clientSocket.onerror = (e) => console.error("客户端WebSocket错误:", e);
    serverSocket.onerror = (e) => console.error("服务器WebSocket错误:", e);
    
    // 关闭处理
    clientSocket.onclose = (e) => {
      console.log(`客户端WebSocket已关闭: ${e.code} ${e.reason}`);
      if (serverSocket.readyState === WebSocket.OPEN) {
        serverSocket.close(e.code, e.reason);
      }
    };
    
    serverSocket.onclose = (e) => {
      console.log(`服务器WebSocket已关闭: ${e.code} ${e.reason}`);
      if (clientSocket.readyState === WebSocket.OPEN) {
        clientSocket.close(e.code, e.reason);
      }
    };
    
    return response;
  } catch (error) {
    console.error("WebSocket处理错误:", error);
    return new Response("WebSocket Error: " + error.message, { status: 500 });
  }
}

console.log(`API多服务代理运行在 http://localhost:${PORT}/`);
