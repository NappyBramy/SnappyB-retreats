const crypto = require('crypto');

function aesEncrypt(password, ticketKey) {
  const key = Buffer.from(ticketKey.substring(0, 32), 'hex');
  const pwd = Buffer.alloc(16, 0);
  Buffer.from(password).copy(pwd);
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(pwd), cipher.final()]);
  return encrypted.toString('hex').toUpperCase();
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') return res.status(200).end();
  
  const { action, accessId, accessSecret, baseUrl, token, deviceId, code, effectiveTime, invalidTime } = req.body;

  const sign = async (str, secret) => {
    return require('crypto').createHmac('sha256', secret).update(str).digest('hex').toUpperCase();
  };

  const sha256 = (str) => require('crypto').createHash('sha256').update(str).digest('hex');

  const tuyaRequest = async (method, path, body, accessToken) => {
    const t = Date.now().toString();
    const nonce = require('crypto').randomBytes(8).toString('hex');
    const bodyHash = sha256(body || '');
    const strToSign = accessId + (accessToken || '') + t + nonce + `${method}\n${bodyHash}\n\n${path}`;
    const signature = await sign(strToSign, accessSecret);
    
    const headers = {
      'client_id': accessId,
      't': t,
      'nonce': nonce,
      'sign': signature,
      'sign_method': 'HMAC-SHA256',
      'Content-Type': 'application/json'
    };
    if (accessToken) headers['access_token'] = accessToken;

    const response = await fetch(baseUrl + path, {
      method,
      headers,
      body: body || undefined
    });
    return response.json();
  };

  try {
    if (action === 'getToken') {
      const result = await tuyaRequest('GET', '/v1.0/token?grant_type=1', null, null);
      return res.json(result);
    }

    if (action === 'setPassword') {
      // Step 1: Get ticket
      const ticketRes = await tuyaRequest('POST', `/v1.0/devices/${deviceId}/door-lock/password-ticket`, '{}', token);
      if (!ticketRes.success) return res.json(ticketRes);
      
      const { ticket_id, ticket_key } = ticketRes.result;
      
      // Step 2: Encrypt password with AES-128-ECB
      const encryptedPwd = aesEncrypt(code, ticket_key);
      
      // Step 3: Set temp password
      const body = JSON.stringify({
        name: 'Guest_' + Date.now(),
        password: encryptedPwd,
        password_type: 'ticket',
        ticket_id,
        effective_time: effectiveTime,
        invalid_time: invalidTime
      });
      
    const result = await tuyaRequest('POST', `/v1.0/devices/${deviceId}/door-lock/temp-password`, body, token);
return res.json({...result, _debug: {encryptedPwd, ticket_id, body: JSON.parse(body)}});

    return res.json({ success: false, msg: 'Unknown action' });
  } catch(e) {
    return res.json({ success: false, msg: e.toString() });
  }
};
