# Vendored frontend dependencies

Committed rather than fetched at build time: the panel's CSP forbids loading anything off-host, and
a console window should not acquire a build-time network dependency.

| File | Package | Version |
|------|---------|---------|
| `xterm.js`, `xterm.css` | `@xterm/xterm` | 5.5.0 |
| `addon-fit.js` | `@xterm/addon-fit` | 0.10.0 |

Refresh with:

```bash
npm install @xterm/xterm@5.5.0 @xterm/addon-fit@0.10.0
```

then copy `node_modules/@xterm/xterm/lib/xterm.js`, `node_modules/@xterm/xterm/css/xterm.css`, and
`node_modules/@xterm/addon-fit/lib/addon-fit.js` here.
