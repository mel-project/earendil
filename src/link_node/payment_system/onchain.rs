use async_trait::async_trait;
use bytes::Bytes;
use melstructs::{Address, CoinData, CoinID, CoinValue, Denom};
use melwallet::{PrepareTxArgs, StdEd25519Signer};
use std::{str::FromStr, sync::Arc};
use stdcode::StdcodeSerializeExt;
use tmelcrypt::Ed25519SK;

use crate::{LinkStore, NodeId, PaymentSystem};

pub struct OnChain {
    wallet: melwallet::Wallet,
    signer: StdEd25519Signer,
    mel_client: Arc<melprot::Client>,
    store: Arc<LinkStore>,
}

impl OnChain {
    pub fn new(
        wallet: melwallet::Wallet,
        sk: Ed25519SK,
        mel_client: Arc<melprot::Client>,
        store: Arc<LinkStore>,
    ) -> anyhow::Result<Self> {
        let signer = StdEd25519Signer(sk);
        Ok(Self {
            wallet,
            signer,
            mel_client,
            store,
        })
    }
}

#[async_trait]
impl PaymentSystem for OnChain {
    async fn pay(&self, my_id: NodeId, to: &str, amount: u64, ott: &str) -> anyhow::Result<String> {
        // we place (my_id, ott) into `additional_data` so payee can identify our payment
        let payment_output = CoinData {
            covhash: Address::from_str(to)?,
            value: CoinValue(amount.into()),
            denom: Denom::Mel,
            additional_data: (my_id, ott).stdcode().into(),
        };
        let fee_multiplier = self
            .mel_client
            .latest_snapshot()
            .await?
            .current_header()
            .fee_multiplier;
        let tx = self.wallet.prepare_tx(
            PrepareTxArgs {
                kind: melstructs::TxKind::Normal,
                inputs: vec![],
                outputs: vec![payment_output],
                covenants: vec![],
                data: Bytes::new(),
                fee_ballast: 0,
            },
            &self.signer,
            fee_multiplier,
        )?;
        let coin_id = CoinID { txhash: tx.hash_nosigs(), index: 0 };

        self.mel_client
            .latest_snapshot()
            .await?
            .get_raw()
            .send_tx(tx)
            .await??;

        // wait for the tx to confim on the blockchain
        loop {
            let snapshot = self.mel_client.latest_snapshot().await?;
            let coin = snapshot.get_coin(coin_id).await?;
            if let Some(_coin) = coin {
                // return payment coin ID as proof
                return Ok(coin_id.to_string());
            }
        }
    }

    async fn verify_payment(&self, from: NodeId, amount: u64, proof: &str) -> anyhow::Result<Option<String>> {
        let coin_id = stdcode::deserialize(proof.as_bytes())?;
        let snapshot = self.mel_client.latest_snapshot().await?;
        let coin_data = snapshot.get_coin(coin_id).await?;
        if let Some(coin) = coin_data {
            let (id, ott): (NodeId, String) = stdcode::deserialize(&coin.coin_data.additional_data)?;
            if id == from && coin.coin_data.value == CoinValue(amount.into()) && self.store.check_and_consume_ott(&ott).await?.is_some() {
                return Ok(Some(ott.to_string()));
            }
        }
        Ok(None)
    }

    fn my_addr(&self) -> String {
        self.wallet.address.to_string()
    }

    fn name(&self) -> String {
        "on_chain".to_string()
    }
}
