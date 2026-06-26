const crypto = require('crypto');

console.log('TLS 1.3 Node.js Client');

const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const plaintext = Buffer.from('Hello TLS 1.3 from Node.js');

const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();

console.log('Encrypted length:', encrypted.length);
console.log('Tag:', tag.toString('hex'));