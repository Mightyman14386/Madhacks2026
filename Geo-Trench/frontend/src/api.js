// The frontend only renders and sends requests; the backend decides everything.
export const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export async function getHealth() {
  const res = await fetch(`${API_URL}/api/health`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
