export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? '';
export const API_TOKEN = import.meta.env.VITE_API_TOKEN;

type RequestInitExtras = Omit<RequestInit, 'headers'> & {
  headers?: HeadersInit;
};

export async function fetchJson<T>(path: string, init: RequestInitExtras = {}): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...init.headers,
  };

  if (API_TOKEN) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${API_TOKEN}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`Request to ${path} failed: ${response.status} ${message}`);
  }

  return response.json() as Promise<T>;
}
