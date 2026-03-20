// Centralized API and WebSocket configuration.
const fallbackApiBase = 'http://127.0.0.1:8000';
const rawApiBase = import.meta.env.VITE_API_URL || fallbackApiBase;
const resolvedApiUrl = new URL(rawApiBase, window.location.origin);

export const API_BASE_URL = resolvedApiUrl.toString().replace(/\/$/, '');
export const WS_BASE_URL =
  (import.meta.env.VITE_WS_URL || `${resolvedApiUrl.protocol === 'https:' ? 'wss' : 'ws'}://${resolvedApiUrl.host}`).replace(/\/$/, '');
