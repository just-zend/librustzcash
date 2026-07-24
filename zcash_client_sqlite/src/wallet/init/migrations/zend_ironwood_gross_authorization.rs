//! Adds versioned, durable gross-spend authorization for Zend's immediate Ironwood lane.
//!
//! The upgrade deliberately leaves the companion table empty for existing immediate rows. Their
//! historical proposal bytes prove what was selected, but not the maximum gross amount the user
//! authorized, so forward spend-creating transitions remain unavailable instead of fabricating
//! consent. Exact eligible known-unsent failures may be explicitly reauthorized; outcome,
//! terminal, and finality recovery continue under their existing evidence rules.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::zend_ironwood_delivery_control;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x36b6fd64_305f_4f38_aa0b_f953bdfe3b12);
const DEPENDENCIES: &[Uuid] = &[zend_ironwood_delivery_control::MIGRATION_ID];

pub(super) struct Migration;

fn map_upgrade_error(
    error: crate::pool_migration::orchard_ironwood::Error,
) -> WalletMigrationError {
    match error {
        crate::pool_migration::orchard_ironwood::Error::Db(error) => {
            WalletMigrationError::DbError(error)
        }
        error => WalletMigrationError::CorruptedData(error.to_string()),
    }
}

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds durable immediate Ironwood gross-spend authorization without authorizing legacy rows."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        crate::pool_migration::orchard_ironwood::upgrade_immediate_gross_authorization(transaction)
            .map_err(map_upgrade_error)
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Removing this boundary would make a downgrade capable of resuming a spend without the
        // durable authorization record enforced by this schema version.
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };
    use schemerz::Migration as _;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_pool_migration::delivery::{DeliverySchemaProvenance, DeliverySchemaVersion};
    use zcash_protocol::consensus::Network;

    #[test]
    fn migrate_fresh_database_to_gross_authorization_schema() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn dependency_and_down_contract_are_exact() {
        assert_eq!(
            Migration.dependencies(),
            HashSet::from([zend_ironwood_delivery_control::MIGRATION_ID]),
        );
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        assert!(matches!(
            RusqliteMigration::down(&Migration, &tx),
            Err(WalletMigrationError::CannotRevert(id)) if id == MIGRATION_ID
        ));
    }

    #[test]
    fn upgrade_error_mapping_preserves_database_failures() {
        assert!(matches!(
            map_upgrade_error(crate::pool_migration::orchard_ironwood::Error::Db(
                rusqlite::Error::QueryReturnedNoRows,
            )),
            WalletMigrationError::DbError(rusqlite::Error::QueryReturnedNoRows)
        ));
        assert!(matches!(
            map_upgrade_error(crate::pool_migration::orchard_ironwood::Error::Corrupt(
                "delivery v1 schema shape",
            )),
            WalletMigrationError::CorruptedData(reason)
                if reason.contains("delivery v1 schema shape")
        ));
    }

    #[test]
    fn migration_framework_advances_exact_historical_v1_to_v2() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let seed = vec![0xAB; 32];

        WalletMigrator::new()
            .with_seed(Secret::new(seed.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db, &[zend_ironwood_delivery_control::MIGRATION_ID])
            .unwrap();
        let v1: (u32, String) = db
            .conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(v1, (1, "just-zend/librustzcash-delivery-v1".to_owned()));
        let v1_has_authorization_table: bool = db
            .conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_gross_authorization'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!v1_has_authorization_table);

        WalletMigrator::new()
            .with_seed(Secret::new(seed))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db, &[MIGRATION_ID])
            .unwrap();
        let v2: (u32, String) = db
            .conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(v2, (2, "just-zend/librustzcash-delivery-v2".to_owned()));
        let v2_has_authorization_table: bool = db
            .conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_gross_authorization'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(v2_has_authorization_table);
        let foreign_keys_enabled: bool = db
            .conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert!(foreign_keys_enabled);
        assert_eq!(
            crate::pool_migration::orchard_ironwood::delivery_schema_provenance(&db.conn).unwrap(),
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(2).unwrap()),
        );
    }
}
