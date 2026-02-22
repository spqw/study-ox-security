/**
 * Ox Security GraphQL API Client
 *
 * All Ox Security API calls go through a single GraphQL endpoint:
 * POST https://api.cloud.ox.security/api/apollo-gateway
 */

import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// Load .env manually (no deps needed)
function loadEnv() {
  const envPath = resolve(process.cwd(), '.env');
  if (!existsSync(envPath)) return;
  const lines = readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
}

loadEnv();

const API_URL = process.env.OX_API_URL || 'https://api.cloud.ox.security/api/apollo-gateway';
const API_KEY = process.env.OX_API_KEY;

if (!API_KEY) {
  console.error('Error: OX_API_KEY not set. Copy .env.example to .env and add your key.');
  console.error('Get your key from: app.ox.security > Settings > API Key Settings');
  process.exit(1);
}

/**
 * Execute a GraphQL query against the Ox Security API
 */
export async function query(graphqlQuery, variables = {}) {
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': API_KEY,
    },
    body: JSON.stringify({ query: graphqlQuery, variables }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Ox API error (${res.status}): ${text}`);
  }

  const json = await res.json();
  if (json.errors) {
    throw new Error(`GraphQL errors: ${JSON.stringify(json.errors, null, 2)}`);
  }

  return json.data;
}

/**
 * Execute a GraphQL mutation against the Ox Security API
 */
export async function mutate(graphqlMutation, variables = {}) {
  return query(graphqlMutation, variables);
}

export { API_URL, API_KEY };
