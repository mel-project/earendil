use std::collections::HashMap;

use dashmap::DashMap;
use earendil_crypt::{ClientId, RelayFingerprint};
use serde::{Deserialize, Serialize};

pub struct Debts {
    client_incoming_prices: DashMap<ClientId, PriceInfo>,
    client_outgoing_prices: DashMap<ClientId, PriceInfo>,
    relay_incoming_prices: DashMap<RelayFingerprint, PriceInfo>,
    relay_outgoing_prices: DashMap<RelayFingerprint, PriceInfo>,
    client_balances: DashMap<ClientId, Balances>,
    relay_balances: DashMap<RelayFingerprint, Balances>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PriceInfo {
    pub price: u64,
    pub debt_limit: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Balances {
    client_incoming_balance: u64,
    client_outgoing_balance: u64,
    relay_incoming_balance: u64,
    relay_outgoing_balance: u64,
}

impl Debts {
    pub fn new() -> Self {
        Self {
            client_incoming_prices: DashMap::new(),
            client_outgoing_prices: DashMap::new(),
            relay_incoming_prices: DashMap::new(),
            relay_outgoing_prices: DashMap::new(),
            client_balances: DashMap::new(),
            relay_balances: DashMap::new(),
        }
    }

    pub fn insert_client_incoming_price(&self, neigh: ClientId, price: u64, debt_limit: u64) {
        let _ = self
            .client_incoming_prices
            .insert(neigh, PriceInfo { price, debt_limit });
    }

    pub fn insert_relay_incoming_price(
        &self,
        neigh: RelayFingerprint,
        price: u64,
        debt_limit: u64,
    ) {
        let _ = self
            .relay_incoming_prices
            .insert(neigh, PriceInfo { price, debt_limit });
    }

    pub fn insert_client_outgoing_price(&self, neigh: ClientId, price: u64, debt_limit: u64) {
        let _ = self
            .client_outgoing_prices
            .insert(neigh, PriceInfo { price, debt_limit });
    }

    pub fn insert_relay_outgoing_price(
        &self,
        neigh: RelayFingerprint,
        price: u64,
        debt_limit: u64,
    ) {
        let _ = self
            .relay_outgoing_prices
            .insert(neigh, PriceInfo { price, debt_limit });
    }

    pub fn incr_relay_outgoing(&self, neigh: RelayFingerprint) {
        if let Some(price_info) = self.relay_outgoing_prices.get(&neigh) {
            let to_add = price_info.price;
            self.relay_balances
                .entry(neigh)
                .or_default()
                .relay_outgoing_balance += to_add;
        }
    }

    pub fn incr_client_incoming(&self, neigh: ClientId) {
        if let Some(price_info) = self.client_incoming_prices.get(&neigh) {
            let to_add = price_info.price;
            self.client_balances
                .entry(neigh)
                .or_default()
                .client_incoming_balance += to_add;
        }
    }

    pub fn incr_relay_incoming(&self, neigh: RelayFingerprint) {
        if let Some(price_info) = self.relay_incoming_prices.get(&neigh) {
            let to_add = price_info.price;
            self.relay_balances
                .entry(neigh)
                .or_default()
                .relay_incoming_balance += to_add;
        }
    }

    fn insert_client_incoming(&self, neigh: ClientId, new_debt: u64) {
        self.client_balances
            .entry(neigh)
            .or_default()
            .client_incoming_balance = new_debt;
    }

    fn insert_relay_incoming(&self, neigh: RelayFingerprint, new_debt: u64) {
        self.relay_balances
            .entry(neigh)
            .or_default()
            .relay_incoming_balance = new_debt;
    }

    pub fn client_net_debt_est(&self, neigh: &ClientId) -> Option<i128> {
        self.client_balances
            .get(neigh)
            .map(|b| b.client_incoming_balance as i128 - b.client_outgoing_balance as i128)
    }

    pub fn relay_net_debt_est(&self, neigh: &RelayFingerprint) -> Option<i128> {
        self.relay_balances
            .get(neigh)
            .map(|b| b.relay_incoming_balance as i128 - b.relay_outgoing_balance as i128)
    }

    pub fn client_is_within_debt_limit(&self, neigh: &ClientId) -> bool {
        if let Some(price_info) = self.client_incoming_prices.get(neigh) {
            if let Some(net) = self.client_net_debt_est(neigh) {
                if net > price_info.debt_limit as i128 {
                    return false;
                }
            }
        }
        true
    }

    pub fn relay_is_within_debt_limit(&self, neigh: &RelayFingerprint) -> bool {
        if let Some(price_info) = self.relay_incoming_prices.get(neigh) {
            if let Some(net) = self.relay_net_debt_est(neigh) {
                if net > price_info.debt_limit as i128 {
                    return false;
                }
            }
        }
        true
    }

    pub fn list(&self) -> Vec<String> {
        let client_balances = self.client_balances.iter().map(|entry| {
            let fp = entry.key();
            if let Some(debt) = self.client_net_debt_est(fp) {
                format!("{fp} owes me {debt} micromel")
            } else {
                format!("no debt found for {fp}")
            }
        });

        let relay_balances = self.relay_balances.iter().map(|entry| {
            let fp = entry.key();
            if let Some(debt) = self.relay_net_debt_est(fp) {
                format!("{fp} owes me {debt} micromel")
            } else {
                format!("no debt found for {fp}")
            }
        });

        client_balances
            .chain(relay_balances)
            .collect::<Vec<String>>()
    }

    pub fn deduct_client_settlement(&self, neigh: ClientId, amount: u64) {
        if let Some(current_debt) = self.client_net_debt_est(&neigh) {
            let debt = current_debt - amount as i128;
            let settled_debt = if debt > 0 { debt as u64 } else { 0 };
            self.insert_client_incoming(neigh, settled_debt);
        }
    }

    pub fn deduct_relay_settlement(&self, neigh: RelayFingerprint, amount: u64) {
        if let Some(current_debt) = self.relay_net_debt_est(&neigh) {
            let debt = current_debt - amount as i128;
            let settled_debt = if debt > 0 { debt as u64 } else { 0 };
            self.insert_relay_incoming(neigh, settled_debt);
        }
    }

    pub fn as_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let client_incoming_prices: HashMap<ClientId, PriceInfo> = self
            .client_incoming_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let relay_incoming_prices: HashMap<RelayFingerprint, PriceInfo> = self
            .relay_incoming_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let client_outgoing_prices: HashMap<ClientId, PriceInfo> = self
            .client_outgoing_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let relay_outgoing_prices: HashMap<RelayFingerprint, PriceInfo> = self
            .relay_outgoing_prices
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let client_balances: HashMap<ClientId, Balances> = self
            .client_balances
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();
        let relay_balances: HashMap<RelayFingerprint, Balances> = self
            .relay_balances
            .iter()
            .map(|item| (*item.key(), item.value().clone()))
            .collect();

        Ok(stdcode::serialize(&(
            client_incoming_prices,
            relay_incoming_prices,
            client_outgoing_prices,
            relay_outgoing_prices,
            client_balances,
            relay_balances,
        ))?)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Debts> {
        let (
            client_incoming_prices,
            relay_incoming_prices,
            client_outgoing_prices,
            relay_outgoing_prices,
            client_balances,
            relay_balances,
        ): (
            HashMap<ClientId, PriceInfo>,
            HashMap<RelayFingerprint, PriceInfo>,
            HashMap<ClientId, PriceInfo>,
            HashMap<RelayFingerprint, PriceInfo>,
            HashMap<ClientId, Balances>,
            HashMap<RelayFingerprint, Balances>,
        ) = stdcode::deserialize(&bytes)?;

        let client_incoming_prices: DashMap<ClientId, PriceInfo> =
            client_incoming_prices.into_iter().collect();
        let relay_incoming_prices: DashMap<RelayFingerprint, PriceInfo> =
            relay_incoming_prices.into_iter().collect();
        let client_outgoing_prices: DashMap<ClientId, PriceInfo> =
            client_outgoing_prices.into_iter().collect();
        let relay_outgoing_prices: DashMap<RelayFingerprint, PriceInfo> =
            relay_outgoing_prices.into_iter().collect();
        let client_balances: DashMap<ClientId, Balances> = client_balances.into_iter().collect();
        let relay_balances: DashMap<RelayFingerprint, Balances> =
            relay_balances.into_iter().collect();

        Ok(Debts {
            client_incoming_prices,
            relay_incoming_prices,
            client_outgoing_prices,
            relay_outgoing_prices,
            client_balances,
            relay_balances,
        })
    }
}
