# api-service (internal)

Internal Axum-based API service for the RSRP workspace.

- `publish = false`
- not intended for `crates.io` in the soft launch phase

## Run

```bash
cargo run -p api-service
```

## Security configuration notes

- Production JWT verification must use `JWT_PUBLIC_KEY_PATH`; inline `JWT_PUBLIC_KEY_PEM` is rejected in production and cannot be combined with the file-based setting.
- `AUDIT_PUBLICATION_SIGNING_PROVIDER=software-ed25519` now requires an explicit `AUDIT_PUBLICATION_SIGNING_SECRET` of at least 32 bytes.
- `AUDIT_PUBLICATION_SIGNING_SECRET` is rejected unless the provider is explicitly set to `software-ed25519`.
- `AUDIT_PUBLICATION_SIGNING_PROVIDER=softhsm` and `AUDIT_PUBLICATION_SIGNING_PROVIDER=none` require `AUDIT_PUBLICATION_SIGNING_SECRET` to be unset.

## Roadmap

- extract reusable Axum integration crate (`rsrp-axum`) if needed
- keep service-specific wiring here
