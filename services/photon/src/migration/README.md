# Running Migrator CLI

- Apply all pending migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration
    ```
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- up
    ```
- Apply first 10 pending migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- up -n 10
    ```
- Rollback last applied migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- down
    ```
- Rollback last 10 applied migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- down -n 10
    ```
- Drop all tables from the database, then reapply all migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- fresh
    ```
- Rollback all applied migrations, then reapply all migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- refresh
    ```
- Rollback all applied migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- reset
    ```
- Check the status of all migrations
    ```sh
    cargo run -p photon-indexer --bin photon-migration -- status
    ```
