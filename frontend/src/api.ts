import { auth } from "@/auth";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

export async function apiFetch(path: string, init: RequestInit = {}) {
  const session = await auth();

  if (!session?.backendToken) {
    throw new Error("Not authenticated");
  }

  const headers = new Headers(init.headers || {});
  headers.set("Authorization", `Bearer ${session.backendToken}`);

  if (!(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  return response;
}