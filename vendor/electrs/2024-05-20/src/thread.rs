use anyhow::Result;

#[cfg(feature = "vendor_electrs")]
pub type JoinHandle = tokio::task::JoinHandle<Result<()>>;
#[cfg(not(feature = "vendor_electrs"))]
pub type JoinHandle = std::thread::JoinHandle<Result<()>>;

pub(crate) fn spawn<F>(name: &'static str, f: F) -> JoinHandle
where
    F: 'static + Send + FnOnce() -> Result<()>,
{
    #[cfg(feature = "vendor_electrs")]
    {
        tokio::task::spawn_blocking(move || run(name, f))
    }

    #[cfg(not(feature = "vendor_electrs"))]
    {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || run(name, f))
            .expect("failed to spawn a thread")
    }
}

fn run<F>(name: &'static str, f: F) -> Result<()>
where
    F: 'static + Send + FnOnce() -> Result<()>,
{
    match f() {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!(
                target: "vendor::electrs::thread",
                %name,
                error = %err,
                "blocking task terminated with error"
            );
            for (index, source) in err.chain().skip(1).enumerate() {
                tracing::warn!(
                    target: "vendor::electrs::thread",
                    %name,
                    source_index = index + 1,
                    source = %source,
                    "error source"
                );
            }
            Err(err)
        }
    }
}

#[cfg(all(test, feature = "vendor_electrs"))]
mod tests {
    use super::spawn;
    use anyhow::{anyhow, Result};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to construct test runtime")
    }

    #[test]
    fn propagates_error_result() {
        let rt = runtime();
        let outcome = rt.block_on(async {
            let handle = spawn("error-task", || Err(anyhow!("test failure")));
            handle.await
        });

        match outcome {
            Ok(Err(err)) => assert_eq!(err.to_string(), "test failure"),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn propagates_panics() {
        let rt = runtime();
        let outcome = rt.block_on(async {
            let handle = spawn("panic-task", || -> Result<()> {
                panic!("boom");
            });
            handle.await
        });

        let err = outcome.expect_err("panic should propagate as JoinError");
        assert!(err.is_panic(), "expected panic JoinError, got {err:?}");
    }
}
