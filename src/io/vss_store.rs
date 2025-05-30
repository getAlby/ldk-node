// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use crate::io::utils::check_namespace_key_validity;
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use lightning::io::{self, Error, ErrorKind};
use lightning::util::persist::{
	KVStore, NETWORK_GRAPH_PERSISTENCE_KEY, NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE,
	NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE,
};
use prost::Message;
use rand::RngCore;
#[cfg(test)]
use std::panic::RefUnwindSafe;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::VssHeaderProvider;
use vss_client::types::{
	DeleteObjectRequest, GetObjectRequest, KeyValue, ListKeyVersionsRequest, PutObjectRequest,
	Storable,
};
use vss_client::util::key_obfuscator::KeyObfuscator;
use vss_client::util::retry::{
	ExponentialBackoffRetryPolicy, FilteredRetryPolicy, JitteredRetryPolicy,
	MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};
use vss_client::util::storable_builder::{EntropySource, StorableBuilder};

type CustomRetryPolicy = FilteredRetryPolicy<
	JitteredRetryPolicy<
		MaxTotalDelayRetryPolicy<MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<VssError>>>,
	>,
	Box<dyn Fn(&VssError) -> bool + 'static + Send + Sync>,
>;

/// A [`KVStore`] implementation that writes to and reads from a [VSS](https://github.com/lightningdevkit/vss-server/blob/main/README.md) backend.
pub struct VssStore {
	client: VssClient<CustomRetryPolicy>,
	store_id: String,
	runtime: Runtime,
	storable_builder: StorableBuilder<RandEntropySource>,
	key_obfuscator: KeyObfuscator,
	secondary_kv_store: Arc<dyn KVStore + Send + Sync>,
}

impl VssStore {
	pub(crate) fn new(
		base_url: String, store_id: String, vss_seed: [u8; 32],
		header_provider: Arc<dyn VssHeaderProvider>,
		secondary_kv_store: Arc<dyn KVStore + Send + Sync>,
	) -> io::Result<Self> {
		let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
		let (data_encryption_key, obfuscation_master_key) =
			derive_data_encryption_and_obfuscation_keys(&vss_seed);
		let key_obfuscator = KeyObfuscator::new(obfuscation_master_key);
		let storable_builder = StorableBuilder::new(data_encryption_key, RandEntropySource);
		let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(10))
			.with_max_attempts(10)
			.with_max_total_delay(Duration::from_secs(15))
			.with_max_jitter(Duration::from_millis(10))
			.skip_retry_on_error(Box::new(|e: &VssError| {
				matches!(
					e,
					VssError::NoSuchKeyError(..)
						| VssError::InvalidRequestError(..)
						| VssError::ConflictError(..)
				)
			}) as _);

		let client = VssClient::new_with_headers(base_url, retry_policy, header_provider);
		Ok(Self { client, store_id, runtime, storable_builder, key_obfuscator, secondary_kv_store })
	}

	fn build_key(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<String> {
		let obfuscated_key = self.key_obfuscator.obfuscate(key);
		if primary_namespace.is_empty() {
			Ok(obfuscated_key)
		} else {
			Ok(format!("{}#{}#{}", primary_namespace, secondary_namespace, obfuscated_key))
		}
	}

	fn extract_key(&self, unified_key: &str) -> io::Result<String> {
		let mut parts = unified_key.splitn(3, '#');
		let (_primary_namespace, _secondary_namespace) = (parts.next(), parts.next());
		match parts.next() {
			Some(obfuscated_key) => {
				let actual_key = self.key_obfuscator.deobfuscate(obfuscated_key)?;
				Ok(actual_key)
			},
			None => Err(Error::new(ErrorKind::InvalidData, "Invalid key format")),
		}
	}

	async fn list_all_keys(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> io::Result<Vec<String>> {
		let mut page_token = None;
		let mut keys = vec![];
		let key_prefix = format!("{}#{}", primary_namespace, secondary_namespace);
		while page_token != Some("".to_string()) {
			let request = ListKeyVersionsRequest {
				store_id: self.store_id.clone(),
				key_prefix: Some(key_prefix.clone()),
				page_token,
				page_size: None,
			};

			let response = self.client.list_key_versions(&request).await.map_err(|e| {
				let msg = format!(
					"Failed to list keys in {}/{}: {}",
					primary_namespace, secondary_namespace, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

			for kv in response.key_versions {
				keys.push(self.extract_key(&kv.key)?);
			}
			page_token = response.next_page_token;
		}
		Ok(keys)
	}
}

impl KVStore for VssStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<Vec<u8>> {
		// Alby: write network graph to secondary storage
		if primary_namespace == NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == NETWORK_GRAPH_PERSISTENCE_KEY
		{
			return self.secondary_kv_store.read(primary_namespace, secondary_namespace, key);
		}

		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "read")?;
		let request = GetObjectRequest {
			store_id: self.store_id.clone(),
			key: self.build_key(primary_namespace, secondary_namespace, key)?,
		};

		let resp =
			tokio::task::block_in_place(|| self.runtime.block_on(self.client.get_object(&request)))
				.map_err(|e| {
					let msg = format!(
						"Failed to read from key {}/{}/{}: {}",
						primary_namespace, secondary_namespace, key, e
					);
					match e {
						VssError::NoSuchKeyError(..) => Error::new(ErrorKind::NotFound, msg),
						_ => Error::new(ErrorKind::Other, msg),
					}
				})?;
		// unwrap safety: resp.value must be always present for a non-erroneous VSS response, otherwise
		// it is an API-violation which is converted to [`VssError::InternalServerError`] in [`VssClient`]
		let storable = Storable::decode(&resp.value.unwrap().value[..]).map_err(|e| {
			let msg = format!(
				"Failed to decode data read from key {}/{}/{}: {}",
				primary_namespace, secondary_namespace, key, e
			);
			Error::new(ErrorKind::Other, msg)
		})?;

		Ok(self.storable_builder.deconstruct(storable)?.0)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: &[u8],
	) -> io::Result<()> {
		// Alby: write network graph to secondary storage
		if primary_namespace == NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == NETWORK_GRAPH_PERSISTENCE_KEY
		{
			return self.secondary_kv_store.write(primary_namespace, secondary_namespace, key, buf);
		}

		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "write")?;
		let version = -1;
		let storable = self.storable_builder.build(buf.to_vec(), version);
		let request = PutObjectRequest {
			store_id: self.store_id.clone(),
			global_version: None,
			transaction_items: vec![KeyValue {
				key: self.build_key(primary_namespace, secondary_namespace, key)?,
				version,
				value: storable.encode_to_vec(),
			}],
			delete_items: vec![],
		};

		tokio::task::block_in_place(|| self.runtime.block_on(self.client.put_object(&request)))
			.map_err(|e| {
				let msg = format!(
					"Failed to write to key {}/{}/{}: {}",
					primary_namespace, secondary_namespace, key, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;

		Ok(())
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool,
	) -> io::Result<()> {
		// Alby: write network graph to secondary storage
		if primary_namespace == NETWORK_GRAPH_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary_namespace == NETWORK_GRAPH_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == NETWORK_GRAPH_PERSISTENCE_KEY
		{
			return self.secondary_kv_store.remove(
				primary_namespace,
				secondary_namespace,
				key,
				_lazy,
			);
		}
		check_namespace_key_validity(primary_namespace, secondary_namespace, Some(key), "remove")?;
		let request = DeleteObjectRequest {
			store_id: self.store_id.clone(),
			key_value: Some(KeyValue {
				key: self.build_key(primary_namespace, secondary_namespace, key)?,
				version: -1,
				value: vec![],
			}),
		};

		tokio::task::block_in_place(|| self.runtime.block_on(self.client.delete_object(&request)))
			.map_err(|e| {
				let msg = format!(
					"Failed to delete key {}/{}/{}: {}",
					primary_namespace, secondary_namespace, key, e
				);
				Error::new(ErrorKind::Other, msg)
			})?;
		Ok(())
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
		check_namespace_key_validity(primary_namespace, secondary_namespace, None, "list")?;

		let keys = tokio::task::block_in_place(|| {
			self.runtime.block_on(self.list_all_keys(primary_namespace, secondary_namespace))
		})
		.map_err(|e| {
			let msg = format!(
				"Failed to retrieve keys in namespace: {}/{} : {}",
				primary_namespace, secondary_namespace, e
			);
			Error::new(ErrorKind::Other, msg)
		})?;

		// Alby: also list keys from secondary storage
		let secondary_keys =
			self.secondary_kv_store.list(primary_namespace, secondary_namespace)?;

		let all_keys: Vec<String> =
			keys.iter().cloned().chain(secondary_keys.iter().cloned()).collect();
		Ok(all_keys)
	}
}

fn derive_data_encryption_and_obfuscation_keys(vss_seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
	let hkdf = |initial_key_material: &[u8], salt: &[u8]| -> [u8; 32] {
		let mut engine = HmacEngine::<sha256::Hash>::new(salt);
		engine.input(initial_key_material);
		Hmac::from_engine(engine).to_byte_array()
	};

	let prk = hkdf(vss_seed, b"pseudo_random_key");
	let k1 = hkdf(&prk, b"data_encryption_key");
	let k2 = hkdf(&prk, &[&k1[..], b"obfuscation_key"].concat());
	(k1, k2)
}

/// A source for generating entropy/randomness using [`rand`].
pub(crate) struct RandEntropySource;

impl EntropySource for RandEntropySource {
	fn fill_bytes(&self, buffer: &mut [u8]) {
		rand::thread_rng().fill_bytes(buffer);
	}
}

#[cfg(test)]
impl RefUnwindSafe for VssStore {}

#[cfg(test)]
#[cfg(vss_test)]
mod tests {
	use super::*;
	use crate::io::test_utils::do_read_write_remove_list_persist;
	use rand::distributions::Alphanumeric;
	use rand::{thread_rng, Rng, RngCore};
	use std::collections::HashMap;
	use vss_client::headers::FixedHeaders;

	#[test]
	fn read_write_remove_list_persist() {
		let vss_base_url = std::env::var("TEST_VSS_BASE_URL").unwrap();
		let mut rng = thread_rng();
		let rand_store_id: String = (0..7).map(|_| rng.sample(Alphanumeric) as char).collect();
		let mut vss_seed = [0u8; 32];
		rng.fill_bytes(&mut vss_seed);
		let header_provider = Arc::new(FixedHeaders::new(HashMap::new()));
		let vss_store =
			VssStore::new(vss_base_url, rand_store_id, vss_seed, header_provider).unwrap();

		do_read_write_remove_list_persist(&vss_store);
	}
}
