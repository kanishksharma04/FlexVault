// Central API URL resolution used across the frontend
// - Set `VITE_API_URL` in production to point to your API (e.g. https://api.example.com/api)
// - During local development, default to http://localhost:3001/api
export const API_URL = import.meta.env.VITE_API_URL
  || (typeof window !== 'undefined' && window.location.hostname === 'localhost'
    ? 'http://localhost:3001/api'
    : (typeof window !== 'undefined' ? `${window.location.origin}/api` : '/api'));

export default API_URL;
