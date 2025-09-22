pub mod api;
pub mod kv;
pub mod pruning;
pub mod schema;
pub mod state;
pub mod tree;
pub mod wal;

#[cfg(test)]
mod tests {
    use super::state::{StateManager, StateReader, StateRoot, StateTransaction};

    struct NoopState;

    #[derive(Clone)]
    struct NoopReader;

    struct NoopTransaction;

    #[derive(Debug)]
    struct Error;

    impl StateReader for NoopReader {
        type Error = Error;

        fn get_raw(&self, _schema: &str, _key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }

        fn root_hash(&self) -> StateRoot {
            Vec::new()
        }
    }

    impl StateTransaction for NoopTransaction {
        type Error = Error;

        fn put_raw(&mut self, _schema: &str, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), Self::Error> {
            Ok(())
        }

        fn delete_raw(&mut self, _schema: &str, _key: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn commit(self) -> Result<StateRoot, Self::Error> {
            Ok(Vec::new())
        }

        fn rollback(self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl StateManager for NoopState {
        type Error = Error;
        type Transaction = NoopTransaction;
        type Reader = NoopReader;

        fn reader(&self) -> Result<Self::Reader, Self::Error> {
            Ok(NoopReader)
        }

        fn begin_transaction(&self) -> Result<Self::Transaction, Self::Error> {
            Ok(NoopTransaction)
        }
    }

    #[test]
    fn traits_can_be_implemented() {
        let state = NoopState;
        let reader = state.reader().expect("reader");
        assert!(reader.root_hash().is_empty());

        let tx = state.begin_transaction().expect("tx");
        tx.commit().expect("commit");
    }
}
