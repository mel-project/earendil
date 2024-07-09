use anyhow::Context;
use async_trait::async_trait;
use base32::Alphabet;
use bytes::Bytes;
use melstructs::{Address, BlockHeight, CoinData, CoinID, CoinValue, Denom, NetID};
use melwallet::{PrepareTxArgs, StdEd25519Signer};
use smol::Timer;
use std::{collections::BTreeMap, str::FromStr, sync::Arc, time::Duration};
use stdcode::StdcodeSerializeExt;
use tmelcrypt::Ed25519SK;

use crate::{NodeId, PaymentSystem};

pub struct OnChain {
    wallet: melwallet::Wallet,
    signer: StdEd25519Signer,
    mel_client: Arc<melprot::Client>,
}

impl OnChain {
    pub fn new(secret: &str, mel_client: Arc<melprot::Client>) -> anyhow::Result<Self> {
        let secret =
            base32::decode(Alphabet::Crockford, secret).context("failed to decode mel secret")?;
        let sk = ed25519_dalek::SigningKey::from_bytes(secret.as_slice().try_into()?);
        let pk = sk.verifying_key();
        let mut vv = [0u8; 64];
        vv[0..32].copy_from_slice(&sk.to_bytes());
        vv[32..].copy_from_slice(&pk.to_bytes());
        let sk = Ed25519SK::from_bytes(&vv).unwrap();
        let signer: StdEd25519Signer = StdEd25519Signer(sk);
        let cov = melvm::Covenant::std_ed25519_pk_new(sk.to_public());
        let addr = cov.hash();
        let wallet = melwallet::Wallet {
            address: addr,
            height: BlockHeight(0),
            confirmed_utxos: BTreeMap::new(),
            pending_outgoing: BTreeMap::new(),
            netid: NetID::Mainnet,
        };

        Ok(Self {
            wallet,
            signer,
            mel_client,
        })
    }
}

#[async_trait]
impl PaymentSystem for OnChain {
    async fn pay(&self, my_id: NodeId, to: &str, amount: u64, ott: &str) -> anyhow::Result<String> {
        tracing::debug!("initiating on-chain payment of {amount} micromel to {to} with code {ott}");
        let mut wallet = self.wallet.clone();
        // we place (my_id, ott) into `additional_data` so payee can identify our payment
        let payment_output = CoinData {
            covhash: Address::from_str(to)?,
            value: CoinValue(amount.into()),
            denom: Denom::Mel,
            additional_data: serde_json::to_string(&(my_id, ott))?.into_bytes().into(),
        };
        let snapshot = self.mel_client.latest_snapshot().await?;

        // sync wallet before preparing tx
        if let Some(owned_coins) = snapshot.get_coins(wallet.address).await? {
            // is this check necessary?
            tracing::debug!("syncing wallet...");
            wallet.full_reset(snapshot.current_header().height, owned_coins)?
        }

        // prepare + send tx
        let fee_multiplier = snapshot.current_header().fee_multiplier;
        let tx = wallet.prepare_tx(
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
        let coin_id = CoinID {
            txhash: tx.hash_nosigs(),
            index: 0,
        };
        snapshot.get_raw().send_tx(tx.clone()).await??;
        tracing::debug!("payment transaction sent");

        // wait for the tx to confim on the blockchain
        let mut current_height = wallet.height;
        loop {
            Timer::after(Duration::from_secs(5)).await;
            let latest_snapshot = self.mel_client.latest_snapshot().await?;
            let latest_height = latest_snapshot.current_header().height;

            if current_height < latest_height {
                if let Some(_coin) = latest_snapshot.get_coin(coin_id).await? {
                    // return payment coin ID as proof
                    tracing::debug!("obtained OnChain proof!");
                    return Ok(coin_id.to_string());
                }
                current_height = latest_height;
            }
            // resend tx in case it got dropped
            let _ = latest_snapshot.get_raw().send_tx(tx.clone()).await;
        }
    }

    async fn verify_payment(
        &self,
        from: NodeId,
        amount: u64,
        proof: &str,
    ) -> anyhow::Result<Option<String>> {
        let coin_id = CoinID::from_str(proof)?;
        let snapshot = self.mel_client.latest_snapshot().await?;
        let coin_data = snapshot.get_coin(coin_id).await?;
        if let Some(coin) = coin_data {
            let (id, ott): (NodeId, String) =
                serde_json::from_str(&String::from_utf8(coin.coin_data.additional_data.to_vec())?)?;
            if id == from && coin.coin_data.value == CoinValue(amount.into()) {
                tracing::debug!("payment verified");
                return Ok(Some(ott));
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

    fn max_granularity(&self) -> u64 {
        u64::MAX
    }
}
