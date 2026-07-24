//! Adds Zend's delivery-control and legacy-cutover quarantine tables after the canonical ZIP 318
//! pool-migration schema. The canonical migration tables remain unchanged and authoritative.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::{note_locking, orchard_ironwood_migration_tables};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xd14c3f72_6f26_4b8a_9d55_17b9e641a2c0);
const DEPENDENCIES: &[Uuid] = &[
    orchard_ironwood_migration_tables::MIGRATION_ID,
    note_locking::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds Zend crash-safe delivery control and legacy Ironwood migration quarantine."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        crate::pool_migration::orchard_ironwood::init_delivery_control_tables(transaction)?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // Delivery claims may retain exact bytes whose network outcome is unknown. Dropping this
        // schema is therefore never an automatic/reversible migration.
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemerz::Migration as _;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    const HISTORICAL_ZCASHLC_INVALID_MARKS_TABLE: &str =
        "ext_zcashlc_orchard_ironwood_migration_invalid_marks";
    const HISTORICAL_INVALID_MARK_HEIGHT: i64 = 1;
    const EXPECTED_LEGACY_ROW_COUNT: u64 = 1;
    const EXPECTED_QUARANTINE_DISPOSITION: &str = "recovery_required";
    const TEST_SEED_BYTE: u8 = 0xab;
    const TEST_SEED_LENGTH: usize = 32;

    #[test]
    fn migrate_fresh_database_to_delivery_schema() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    fn migration_quarantines_historical_zcashlc_invalid_marks() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();
        let seed = vec![TEST_SEED_BYTE; TEST_SEED_LENGTH];

        WalletMigrator::new()
            .with_seed(Secret::new(seed.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();
        db_data
            .conn
            .execute(
                &format!(
                    "CREATE TABLE {HISTORICAL_ZCASHLC_INVALID_MARKS_TABLE} (
                         height INTEGER NOT NULL
                     )"
                ),
                [],
            )
            .unwrap();
        db_data
            .conn
            .execute(
                &format!(
                    "INSERT INTO {HISTORICAL_ZCASHLC_INVALID_MARKS_TABLE} (height) VALUES (?)"
                ),
                [HISTORICAL_INVALID_MARK_HEIGHT],
            )
            .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(seed))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let (detected_rows, disposition): (u64, String) = db_data
            .conn
            .query_row(
                "SELECT detected_rows, disposition
                   FROM zend_ironwood_legacy_quarantine
                  WHERE source_object = ?",
                [HISTORICAL_ZCASHLC_INVALID_MARKS_TABLE],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(detected_rows, EXPECTED_LEGACY_ROW_COUNT);
        assert_eq!(disposition, EXPECTED_QUARANTINE_DISPOSITION);
        let retained_rows: u64 = db_data
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {HISTORICAL_ZCASHLC_INVALID_MARKS_TABLE}"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_rows, EXPECTED_LEGACY_ROW_COUNT);
    }

    #[test]
    fn dependency_and_down_contract_are_exact() {
        assert_eq!(
            Migration.dependencies(),
            HashSet::from([
                orchard_ironwood_migration_tables::MIGRATION_ID,
                note_locking::MIGRATION_ID,
            ]),
            "delivery control requires both the canonical migration schema and every wallet note-lock column",
        );
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        assert!(matches!(
            RusqliteMigration::down(&Migration, &tx),
            Err(WalletMigrationError::CannotRevert(id)) if id == MIGRATION_ID
        ));
    }
}
