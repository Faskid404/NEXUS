export const AUTH_KEY = "nxauth_v7";

export const getToken = (): string =>
  sessionStorage.getItem(AUTH_KEY) ?? "";

export const authHeaders = (): Record<string, string> => {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
};

export const withAuthToken = (url: string): string => {
  const t = getToken();
  return t ? `${url}?token=${encodeURIComponent(t)}` : url;
};
