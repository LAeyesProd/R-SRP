# api-service (internal)

Internal Axum-based API service for the RSRP workspace.

- `publish = false`
- not intended for `crates.io` in the soft launch phase

## Run

```bash
cargo run -p api-service
```

## Roadmap

- extract reusable Axum integration crate (`rsrp-axum`) if needed
- keep service-specific wiring here

