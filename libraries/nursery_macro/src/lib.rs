#[macro_export]
macro_rules! nursery {
    ($body:expr) => {{
        let exec = smol::Executor::new();

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

#[cfg(test)]
mod test {
    use std::time::Duration;

    #[test]
    fn simple_nursery() {
        smol::future::block_on(async {
            nursery!({
                println!("test");

                spawn!(async move { println!("world") }).detach();
                smol::Timer::after(Duration::from_secs(1)).await;
            });
        });
    }
}
