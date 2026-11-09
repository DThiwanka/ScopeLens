/**
 * ScopeLens Platform - Core Constants
 */

export const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFORMATIONAL: 'INFORMATIONAL'
};

export const CONFIDENCE = {
  CONFIRMED: 'CONFIRMED',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW'
};

export const MESSAGE_TYPES = {
  START_CAPTURE: 'START_CAPTURE',
  STOP_CAPTURE: 'STOP_CAPTURE',
  GET_CAPTURE: 'GET_CAPTURE',
  CAPTURE_UPDATE: 'CAPTURE_UPDATE',
  DNS_LOOKUP: 'DNS_LOOKUP',
  RECON_PROBE: 'RECON_PROBE',
  SAVE_SNAPSHOT: 'SAVE_SNAPSHOT',
  GET_SNAPSHOTS: 'GET_SNAPSHOTS',
  DELETE_SNAPSHOT: 'DELETE_SNAPSHOT',
  COMPARE_SNAPSHOTS: 'COMPARE_SNAPSHOTS',
  CLEAR_STORAGE: 'CLEAR_STORAGE'
};

export const SENSITIVE_KEY_PATTERN = /cookie|set-cookie|token|auth|bearer|secret|password|passwd|credential|api[_-]?key|client[_-]?secret|session|private[_-]?key|signature|access[_-]?token|refresh[_-]?token/i;

export const JWT_PATTERN = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

export const SECRET_PATTERNS = {
  AWS_KEY: /\bAKIA[0-9A-Z]{16}\b/g,
  GOOGLE_API_KEY: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  GITHUB_TOKEN: /\b(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b/g,
  STRIPE_SECRET: /\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
  STRIPE_PUBLISHABLE: /\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
  SLACK_WEBHOOK: /https:\/\/hooks\.slack\.com\/services\/T[0-9a-zA-Z_]+\/B[0-9a-zA-Z_]+\/[0-9a-zA-Z_]+/g,
  PRIVATE_KEY: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g
};

export const DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'PTR'];

export const RESOURCE_TYPES = {
  DOCUMENT: 'document',
  STYLESHEET: 'stylesheet',
  SCRIPT: 'script',
  IMAGE: 'image',
  FONT: 'font',
  XHR: 'xhr',
  FETCH: 'fetch',
  WEBSOCKET: 'websocket',
  MEDIA: 'media',
  OTHER: 'other'
};
