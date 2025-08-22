# Operational Security

When scanning targets, route traffic through anonymity networks or VPNs to
avoid exposing your home IP.

## Tor

1. Install and start Tor locally.
2. Expose the SOCKS proxy (default `127.0.0.1:9050`).
3. Export the proxy URL before running scans:

```bash
export BH_PROXY_URL="socks5://127.0.0.1:9050"
```

All HTTP requests will be sent through the Tor network.

## VPN

When using a commercial VPN or corporate tunnel, set the proxy to the VPN
endpoint if one is provided:

```bash
export BH_PROXY_URL="http://vpn-proxy.local:8080"
```

Alternatively, run the scanner inside the VPN-protected environment.

Always verify that your traffic is correctly routed before interacting with
third-party systems.
