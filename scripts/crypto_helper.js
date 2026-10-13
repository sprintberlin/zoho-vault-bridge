#!/usr/bin/env node
/**
 * Crypto Helper for Zoho Vault Bridge.
 * Handles zero-knowledge encryption/decryption matching Zoho Vault web and CLI clients.
 */

import crypto from 'node:crypto';
import Zohovault from './vendor/zohovault.js';

export function deriveMasterKey(password, salt, iterations) {
  const saltBuffer = Buffer.from(salt, 'binary');
  const derived = crypto.pbkdf2Sync(
    Buffer.from(password, 'utf8'),
    saltBuffer,
    parseInt(iterations, 10),
    32, // 256 bits = 32 bytes
    'sha256'
  );
  return derived.toString('hex');
}

export function checkLogin(passauthCipher, masterKey) {
  try {
    const decrypted = Zohovault.AES.decrypt(passauthCipher, masterKey, 256);
    const parsed = JSON.parse(decrypted);
    return Boolean(parsed && parsed.date && !isNaN(Date.parse(parsed.date)));
  } catch {
    return false;
  }
}

export function decryptText(ciphertext, key) {
  if (!ciphertext || !key) return '';
  return Zohovault.AES.decrypt(ciphertext, key, 256);
}

export function encryptText(plaintext, key) {
  if (!plaintext || !key) return '';
  return Zohovault.AES.encrypt(plaintext, key, 256);
}

export function rsaDecrypt(ciphertextBase64, privateKeyPem) {
  const buffer = Buffer.from(ciphertextBase64, 'base64');
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    buffer
  );
  return decrypted.toString('utf8');
}

// CLI runner for Python sub-process calls
if (process.argv[1] && process.argv[1].endsWith('crypto_helper.js')) {
  const action = process.argv[2];
  try {
    if (action === 'derive') {
      const password = process.argv[3];
      const salt = process.argv[4];
      const iterations = process.argv[5];
      const key = deriveMasterKey(password, salt, iterations);
      process.stdout.write(JSON.stringify({ status: 'ok', key }));
    } else if (action === 'check_login') {
      const passauth = process.argv[3];
      const key = process.argv[4];
      const valid = checkLogin(passauth, key);
      process.stdout.write(JSON.stringify({ status: 'ok', valid }));
    } else if (action === 'decrypt') {
      const ciphertext = process.argv[3];
      const key = process.argv[4];
      const plaintext = decryptText(ciphertext, key);
      process.stdout.write(JSON.stringify({ status: 'ok', plaintext }));
    } else if (action === 'encrypt') {
      const plaintext = process.argv[3];
      const key = process.argv[4];
      const ciphertext = encryptText(plaintext, key);
      process.stdout.write(JSON.stringify({ status: 'ok', ciphertext }));
    } else if (action === 'decrypt_secret_data') {
      // Input from stdin as JSON: { secretData: {...}, key: "..." }
      let inputData = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => { inputData += chunk; });
      process.stdin.on('end', () => {
        try {
          const { secretData, key } = JSON.parse(inputData);
          let parsedData = typeof secretData === 'string' ? JSON.parse(secretData) : secretData;
          const decrypted = {};
          for (const [field, val] of Object.entries(parsedData)) {
            if (typeof val === 'string' && val.length > 0) {
              decrypted[field] = decryptText(val, key);
            } else {
              decrypted[field] = val;
            }
          }
          process.stdout.write(JSON.stringify({ status: 'ok', decrypted }));
        } catch (err) {
          process.stdout.write(JSON.stringify({ status: 'error', error: err.message }));
        }
      });
    } else if (action === 'encrypt_secret_data') {
      // Input from stdin as JSON: { secretData: {...}, key: "..." }
      let inputData = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => { inputData += chunk; });
      process.stdin.on('end', () => {
        try {
          const { secretData, key } = JSON.parse(inputData);
          const encrypted = {};
          for (const [field, val] of Object.entries(secretData)) {
            if (typeof val === 'string' && val.length > 0) {
              encrypted[field] = encryptText(val, key);
            } else {
              encrypted[field] = val;
            }
          }
          process.stdout.write(JSON.stringify({ status: 'ok', encrypted }));
        } catch (err) {
          process.stdout.write(JSON.stringify({ status: 'error', error: err.message }));
        }
      });
    } else {
      process.stderr.write(`Unknown action: ${action}\n`);
      process.exit(1);
    }
  } catch (err) {
    process.stdout.write(JSON.stringify({ status: 'error', error: err.message }));
  }
}
