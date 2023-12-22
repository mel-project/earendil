use dashmap::DashMap;
use earendil_crypt::Fingerprint;

pub struct Debts {
    incoming_prices: DashMap<Fingerprint, PriceInfo>,
    outgoing_prices: DashMap<Fingerprint, PriceInfo>,
    balances: DashMap<Fingerprint, Balances>,
}
pub struct PriceInfo {
    pub price: u64,
    pub debt_limit: u64,
}

#[derive(Default)]
pub struct Balances {
    incoming_balance: u64,
    outgoing_balance: u64,
}

impl Debts {
    pub fn new() -> Self {
        Self {
            incoming_prices: DashMap::new(),
            outgoing_prices: DashMap::new(),
            balances: DashMap::new(),
        }
    }

    pub fn insert_incoming_price(&self, neigh_fp: Fingerprint, price: u64, debt_limit: u64) {
        let _ = self
            .incoming_prices
            .insert(neigh_fp, PriceInfo { price, debt_limit });
    }

    pub fn insert_outgoing_price(
        &self,
        neigh_fp: Fingerprint,
        price: u64,
        debt_limit: u64,
        max_outgoing_price: u64,
    ) {
        let _ = self
            .outgoing_prices
            .insert(neigh_fp, PriceInfo { price, debt_limit });
    }

    pub fn incr_outgoing(&self, their_fp: Fingerprint) {
        if let Some(price_info) = self.outgoing_prices.get(&their_fp) {
            let to_add = price_info.price;
            self.balances.entry(their_fp).or_default().outgoing_balance += to_add;
        }
    }

    pub fn incr_incoming(&self, their_fp: Fingerprint) {
        if let Some(price_info) = self.incoming_prices.get(&their_fp) {
            let to_add = price_info.price;
            self.balances.entry(their_fp).or_default().incoming_balance += to_add;
        }
    }

    pub fn net_debt_est(&self, their_fp: &Fingerprint) -> Option<i128> {
        self.balances
            .get(their_fp)
            .map(|b| b.incoming_balance as i128 - b.outgoing_balance as i128)
    }

    pub fn is_within_debt_limit(&self, their_fp: &Fingerprint) -> bool {
        if let Some(b) = self.incoming_prices.get(&their_fp) {
            if let Some(net) = self.net_debt_est(their_fp) {
                if net > b.debt_limit as i128 {
                    return false;
                }
            }
        }
        true
    }
}
