// Centralized API configuration
// Uses VITE_API_URL from .env file, falls back to localhost
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
