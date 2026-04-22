const crypto = require('crypto');

function aesEncrypt(password, ticketKey) {
  const key = Buffer.from(ticketKey.substring(0, 32), 'hex');
  const pwd = Buffer.alloc(16, 0);
  Buffer.from(password, 'ascii').copy(pwd);
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(pwd), cipher.final()]);
  return encrypted.toString('hex').toUpperCase();
}

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function hmacSign(str, secret) {
  return crypto.createHmac('sha256', secret).update(str).digest('hex').toUpperCase();
}

async function tuyaRequest(method, path, body, accessId, accessSecret, baseUrl, accessToken) {
  const t = Date.now().toString();
  const nonce = crypto.randomBytes(8).toString('hex');
  const bodyHash = sha256(body || '');
  const strToSign = accessId + (accessToken || '') + t + nonce + method + '\n' + bodyHash + '\n\n' + path;
  const signature = hmacSign(strToSign, accessSecret);
  const headers = { 'client_id': accessId, 't': t, 'nonce': nonce, 'sign': signature, 'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json' };
  if (accessToken) headers['access_token'] = accessToken;
  const response = await fetch(baseUrl + path, { method: method, headers: headers, body: body || undefined });
  return response.json();
}

module.exports = async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { return res.status(200).end(); }
  try {
    const { action, accessId, accessSecret, baseUrl, token, deviceId, code, effectiveTime, invalidTime } = req.body;
    if (action === 'getToken') {
      const result = await tuyaRequest('GET', '/v1.0/token?grant_type=1', null, accessId, accessSecret, baseUrl, null);
      return res.json(result);
    }
    if (action === 'setPassword') {
      const ticketRes = await tuyaRequest('POST', '/v1.0/devices/' + deviceId + '/door-lock/password-ticket', '{}', accessId, accessSecret, baseUrl, token);
      if (!ticketRes.success) { return res.json({success: false, msg: 'TICKET: ' + JSON.stringify(ticketRes)}); }
      const ticketId = ticketRes.result.ticket_id;
      const ticketKey = ticketRes.result.ticket_key;
      const encryptedPwd = aesEncrypt(code, ticketKey);
      const pwdBody = JSON.stringify({ name: 'Guest_' + Date.now(), password: encryptedPwd, password_type: 'ticket', ticket_id: ticketId, effective_time: parseInt(effectiveTime), invalid_time: parseInt(invalidTime) });
      const result = await tuyaRequest('POST', '/v1.0/devices/' + deviceId + '/door-lock/temp-password', pwdBody, accessId, accessSecret, baseUrl, token);
      const parsed = JSON.parse(pwdBody);
      return res.json({result: result, sent: parsed});
    }
    return res.json({success: false, msg: 'Unknown action'});
  } catch(err) {
    return res.json({success: false, msg: err.toString()});
  }
};
