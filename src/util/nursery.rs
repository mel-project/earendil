macro_rules! nursery {
    ($body:block) => {{
        let _exec = smol::Executor::new();
        let _exec = &_exec;
        _exec.run(async move { $body }).await
    }};
}

macro_rules! spawn {
    ($val:expr) => {
        _exec.spawn($val)
    };
}

#[cfg(test)]
mod test {
    #[test]
    fn simple_nursery() {
        smolscale::block_on(async {
            nursery!({
                println!("test");
                spawn!(async move { println!("world") }).detach();
            });
        });
    }
}
