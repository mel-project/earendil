#[macro_export]
macro_rules! nursery {
    ($body:expr) => {{
        let exec = $crate::__private::Executor::new();

        {
            // This allows the `spawn!` macro to access `exec` by name
            macro_rules! spawn {
                ($val:expr) => {
                    exec.spawn($val)
                };
            }

            exec.run(async { $body }).await
        }
    }};
}

#[doc(hidden)]
pub mod __private {
    #[doc(hidden)]
    pub use async_executor::Executor;
}
