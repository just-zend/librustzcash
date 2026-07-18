# zcash_pool_migration_sqlite

SQLite persistence for the Zcash Orchard -> Ironwood value-pool migration engine
(ZIP 318).

This crate implements the `PoolMigrationRead` / `PoolMigrationWrite` store traits
from `zcash_pool_migration_backend` over two SQLite tables (`pool_migrations` and
`pool_migration_transactions`), mirroring how `zcash_client_sqlite` implements
`zcash_client_backend`'s `WalletRead` / `WalletWrite`.

`zcash_client_sqlite` depends on this crate (never the reverse): it registers a
thin `schemerz` migration that runs this crate's table DDL, depends on
`ironwood_received_notes`, and exposes the store through its `WalletDb`, so the
pool-migration tables live in the same `wallet.db`.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
