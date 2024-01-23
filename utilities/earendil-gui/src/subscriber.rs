use std::{collections::VecDeque, fmt, fmt::Write, sync::RwLock};

use once_cell::sync::Lazy;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;

pub static LOGS: Lazy<RwLock<VecDeque<String>>> = Lazy::new(|| RwLock::new(VecDeque::new()));
pub struct VecLayer;

pub struct StringVisitor<'a> {
    string: &'a mut String,
}

impl<'a> Visit for StringVisitor<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        write!(self.string, "{} = {:?}; ", field.name(), value).unwrap();
    }
}

impl<S> Layer<S> for VecLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let timestamp = chrono::Local::now().to_string();
        let level = event.metadata().level().as_str();
        let target = event.metadata().target();

        let mut visitor = StringVisitor {
            string: &mut String::new(),
        };
        event.record(&mut visitor);
        let message = visitor.string;

        let log = format!("{timestamp}, {level}, {target}, {message}");
        let mut logs_vec = LOGS.write().unwrap();
        if logs_vec.len() > 2000 {
            logs_vec.pop_front();
        }
        logs_vec.push_back(log);
    }
}
