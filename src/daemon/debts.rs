use std::collections::HashMap;

use dashmap::DashMap;
use earendil_crypt::Fingerprint;
use serde::{Deserialize, Serialize};

pub struct Debts {
    incoming_prices: DashMap<Fingerprint, PriceInfo>,
    outgoing_prices: DashMap<Fingerprint, PriceInfo>,
    balances: DashMap<Fingerprint, Balances>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PriceInfo {
    pub price: u64,
    pub debt_limit: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
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

    pub fn insert_outgoing_price(&self, neigh_fp: Fingerprint, price: u64, debt_limit: u64) {
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

    fn insert_incoming(&self, their_fp: Fingerprint, new_debt: u64) {
        self.balances.entry(their_fp).or_default().incoming_balance = new_debt;
    }

    pub fn net_debt_est(&self, their_fp: &Fingerprint) -> Option<i128> {
        self.balances
            .get(their_fp)
            .map(|b| b.incoming_balance as i128 - b.outgoing_balance as i128)
    }

    pub fn is_within_debt_limit(&self, their_fp: &Fingerprint) -> bool {
        if let Some(price_info) = self.incoming_prices.get(their_fp) {
            if let Some(net) = self.net_debt_est(their_fp) {
                if net > price_info.debt_limit as i128 {
                    return false;
                }
            }
        }
        true
    }

    pub fn list(&self) -> Vec<String> {
        self.balances
            .iter()
            .map(|entry| {
                let fp = entry.key();
                if let Some(debt) = self.net_debt_est(fp) {
                    format!("{fp} owes me {debt} micromel")
                } else {
                    format!("no debt found for {fp}")
                }
            })
            .collect()
    }

    pub fn deduct_settlement(&self, their_fp: Fingerprint, amount: u64) {
        if let Some(current_debt) = self.net_debt_est(&their_fp) {
            let debt = current_debt - amount as i128;
            let settled_debt = if debt > 0 { debt as u64 } else { 0 };
            self.insert_incoming(their_fp, settled_debt);
        }
    }

    pub fn as_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let incoming_prices: HashMap<Fingerprint, PriceInfo> = self
            .incoming_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let outgoing_prices: HashMap<Fingerprint, PriceInfo> = self
            .outgoing_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let balances: HashMap<Fingerprint, Balances> = self
            .balances
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();

        Ok(stdcode::serialize(&(
            incoming_prices,
            outgoing_prices,
            balances,
        ))?)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Debts> {
        let (incoming_prices, outgoing_prices, balances): (
            HashMap<Fingerprint, PriceInfo>,
            HashMap<Fingerprint, PriceInfo>,
            HashMap<Fingerprint, Balances>,
        ) = stdcode::deserialize(&bytes)?;

        let incoming_prices: DashMap<Fingerprint, PriceInfo> =
            incoming_prices.into_iter().collect();
        let outgoing_prices: DashMap<Fingerprint, PriceInfo> =
            outgoing_prices.into_iter().collect();
        let balances: DashMap<Fingerprint, Balances> = balances.into_iter().collect();

        Ok(Debts {
            incoming_prices,
            outgoing_prices,
            balances,
        })
    }
}
