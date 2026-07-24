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
    use crate::wallet::init::migrations::tests::test_migrate;
    use schemerz::Migration as _;

    #[test]
    fn migrate_fresh_database_to_delivery_schema() {
        test_migrate(&[MIGRATION_ID]);
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
