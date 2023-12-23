use std::time::Duration;

use earendil_crypt::{Fingerprint, IdentitySecret};
use moka::sync::Cache;
use parking_lot::Mutex;

use crate::{control_protocol::SendMessageError, daemon::context::send_reply_blocks};

use super::context::{CtxField, DaemonContext};

static LAWK: Mutex<()> = Mutex::new(());

pub fn replenish_rrb(
    ctx: &DaemonContext,
    my_anon_isk: IdentitySecret,
    dst_fp: Fingerprint,
) -> Result<(), SendMessageError> {
    let _guard = LAWK.lock();
    const BATCH_SIZE: usize = 10;
    while rb_balance(ctx, my_anon_isk, dst_fp) < 100.0 {
        // we conservatively assume half get there
        ctx.get(BALANCE_TABLE).insert(
            (my_anon_isk, dst_fp),
            rb_balance(ctx, my_anon_isk, dst_fp) + (BATCH_SIZE / 2) as f64,
        );
        let ctx = ctx.clone();
        smolscale::spawn(
            async move { send_reply_blocks(&ctx, BATCH_SIZE, my_anon_isk, dst_fp).await },
        )
        .detach();
    }
    Ok(())
}

pub fn decrement_rrb_balance(
    ctx: &DaemonContext,
    my_anon_isk: IdentitySecret,
    reply_source: Fingerprint,
) {
    let new_balance = rb_balance(ctx, my_anon_isk, reply_source);
    ctx.get(BALANCE_TABLE)
        .insert((my_anon_isk, reply_source), new_balance - 1.0);
}

fn rb_balance(ctx: &DaemonContext, my_anon_isk: IdentitySecret, reply_source: Fingerprint) -> f64 {
    ctx.get(BALANCE_TABLE)
        .get_with((my_anon_isk, reply_source), || 0.0)
}

static BALANCE_TABLE: CtxField<Cache<(IdentitySecret, Fingerprint), f64>> = |_| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60)) // we don't keep track beyond so if rb calculation is wrong, we don't get stuck for too long
        .build()
};
