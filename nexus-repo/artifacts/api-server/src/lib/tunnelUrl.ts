let _tunnelUrl: string | null = null;

export function setTunnelUrl(url: string): void {
  _tunnelUrl = url;
}

export function getTunnelUrl(): string | null {
  return _tunnelUrl;
}
