// Copyright 2018-2020 Commonwealth Labs, Inc.
// This file is part of Edgeware.

// Edgeware is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Edgeware is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Edgeware.  If not, see <http://www.gnu.org/licenses/>.

#![warn(unused_extern_crates)]

//! Service implementation. Specialized wrapper over substrate service.

use crate::cli::Cli;
use sc_cli::SubstrateCli;
use sc_service::ChainSpec;
use edgeware_executor::{NativeElseWasmExecutor, ExecutorDispatch};
use cli_opt::{EthApi as EthApiCmd, RpcConfig};
use edgeware_primitives::Block;

use edgeware_runtime::RuntimeApi;
use fc_consensus::FrontierBlockImport;
use sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use sp_consensus_aura::ed25519::AuthorityPair as AuraPair;
use sp_core::U256;

use fc_rpc_core::types::FilterPool;
use std::{
	cell::RefCell,
	collections::{BTreeMap, HashMap},
	sync::{Arc, Mutex},
	time::Duration,
};
use sc_client_api::{ExecutorProvider, RemoteBackend, BlockchainEvents};
use sc_finality_grandpa::{self, FinalityProofProvider as GrandpaFinalityProofProvider};
use sc_network::warp_request_handler::WarpSyncProvider;
use sc_service::{
	BasePath, config::{Configuration}, error::{Error as ServiceError},
	RpcHandlers, TaskManager,
};
use sp_inherents::InherentDataProvider;
use sc_network::{Event, NetworkService};
use sp_runtime::traits::Block as BlockT;
use futures::prelude::*;
use sc_telemetry::{Telemetry, TelemetryWorker};
use sp_consensus::SlotData;

type FullClient =
	sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport =
	sc_finality_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>;

pub type ConsensusResult = (
	// FrontierBlockImport<
	// 	Block,
	// 	FullGrandpaBlockImport,
	// 	FullClient,
	// >,
	sc_finality_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
	sc_finality_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
);

type LightClient = sc_service::TLightClient<Block, RuntimeApi, ExecutorDispatch>;

/// Can be called for a `Configuration` to check if it is a configuration for the `Kusama` network.
pub trait IdentifyVariant {
	/// Returns if this is a configuration for the `Kusama` network.
	fn is_mainnet(&self) -> bool;

	/// Returns if this is a configuration for the `Westend` network.
	fn is_beresheet(&self) -> bool;
}

impl IdentifyVariant for Box<dyn ChainSpec> {
	fn is_mainnet(&self) -> bool {
		self.id().starts_with("edgeware") || self.id().starts_with("edg")
	}

	fn is_beresheet(&self) -> bool {
		self.id().starts_with("beresheet") || self.id().starts_with("tedg")
	}
}

pub fn frontier_database_dir(config: &Configuration) -> std::path::PathBuf {
	let config_dir = config
		.base_path
		.as_ref()
		.map(|base_path| base_path.config_dir(config.chain_spec.id()))
		.unwrap_or_else(|| {
			BasePath::from_project("", "", &<crate::cli::Cli as SubstrateCli>::executable_name())
				.config_dir(config.chain_spec.id())
		});
	config_dir.join("frontier").join("db")
}

pub fn open_frontier_backend(config: &Configuration) -> Result<Arc<fc_db::Backend<Block>>, String> {
	Ok(Arc::new(fc_db::Backend::<Block>::new(
		&fc_db::DatabaseSettings {
			source: fc_db::DatabaseSettingsSrc::RocksDb {
				path: frontier_database_dir(&config),
				cache_size: 0,
			},
		},
	)?))
}

pub fn new_partial(
	config: &Configuration,
	cli: &Cli,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(
			ConsensusResult,
			Option<FilterPool>,
			Arc<fc_db::Backend<Block>>,
			Option<Telemetry>,
		),
	>,
	ServiceError,
> {
	if config.keystore_remote.is_some() {
		return Err(ServiceError::Other(format!(
			"Remote Keystores are not supported."
		)));
	}

	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			&config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));

	let frontier_backend = open_frontier_backend(config)?;

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let frontier_block_import = FrontierBlockImport::new(
		grandpa_block_import.clone(),
		client.clone(),
		frontier_backend.clone(),
	);

	let slot_duration = sc_consensus_aura::slot_duration(&*client)?.slot_duration();
	let target_gas_price = cli.run.target_gas_price;

	let import_queue =
		sc_consensus_aura::import_queue::<AuraPair, _, _, _, _,  _, _>(
			ImportQueueParams {
				block_import: grandpa_block_import.clone(),
				justification_import: Some(Box::new(grandpa_block_import.clone())),
				client: client.clone(),
				create_inherent_data_providers: move |_, ()| async move {
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
							*timestamp,
							slot_duration,
						);

					let dynamic_fee =
						pallet_dynamic_fee::InherentDataProvider(U256::from(target_gas_price));

					Ok((timestamp, slot, dynamic_fee))
				},
				spawner: &task_manager.spawn_essential_handle(),
				can_author_with: sp_consensus::CanAuthorWithNativeVersion::new(
					client.executor().clone(),
				),
				registry: config.prometheus_registry(),
				check_for_equivocation: Default::default(),
				telemetry: telemetry.as_ref().map(|x| x.handle()),
			})?;

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (
			(grandpa_block_import, grandpa_link),
			filter_pool,
			frontier_backend,
			telemetry,
		),
	})
}

pub struct NewFullBase {
	pub task_manager: TaskManager,
	pub client: Arc<FullClient>,
	pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
	pub transaction_pool: Arc<sc_transaction_pool::FullPool<Block, FullClient>>,
}

/// Creates a full service from the configuration.
pub fn new_full_base(mut config: Configuration, cli: &Cli) -> Result<NewFullBase, ServiceError> {
	let rpc_config = RpcConfig {
		ethapi: cli.run.ethapi.clone(),
		ethapi_max_permits: cli.run.ethapi_max_permits,
		ethapi_trace_max_count: cli.run.ethapi_trace_max_count,
		ethapi_trace_cache_duration: cli.run.ethapi_trace_cache_duration,
		max_past_logs: cli.run.max_past_logs,
	};

	let enable_dev_signer = cli.run.enable_dev_signer;
	let target_gas_price = U256::from(cli.run.target_gas_price);

	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		mut keystore_container,
		select_chain,
		transaction_pool,
		other: (consensus_result, filter_pool, frontier_backend, mut telemetry),
	} = new_partial(&config, cli)?;

	let warp_sync: Option<Arc<dyn WarpSyncProvider<Block>>> = {
		config
			.network
			.extra_sets
			.push(sc_finality_grandpa::grandpa_peers_set_config());
		Some(Arc::new(
			sc_finality_grandpa::warp_proof::NetworkProvider::new(
				backend.clone(),
				consensus_result.1.shared_authority_set().clone(),
			),
		))
	};

	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: None,
			block_announce_validator_builder: None,
			warp_sync: warp_sync,
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}
	
	let (block_import, grandpa_link) = consensus_result;

	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks: Option<()> = None;
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();
	let is_authority = config.role.is_authority();
	let enable_dev_signer = cli.run.enable_dev_signer;
	let subscription_task_executor =
		sc_rpc::SubscriptionTaskExecutor::new(task_manager.spawn_handle());

	// let spawned_requesters = edgeware_rpc::spawn_tasks(
	// 	&rpc_config,
	// 	edgeware_rpc::SpawnTasksParams {
	// 		task_manager: &task_manager,
	// 		client: client.clone(),
	// 		substrate_backend: backend.clone(),
	// 		frontier_backend: frontier_backend.clone(),
	// 		filter_pool: filter_pool.clone(),
	// 	},
	// );

	// let ethapi_cmd = rpc_config.ethapi.clone();
	let shared_voter_state = sc_finality_grandpa::SharedVoterState::empty();

	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		let network = network.clone();
		let filter_pool = filter_pool.clone();
		let frontier_backend = frontier_backend.clone();
		let backend = backend.clone();
		let ethapi_cmd = rpc_config.ethapi.clone();
		let max_past_logs = rpc_config.max_past_logs;
		let is_authority = role.is_authority();
		let select_chain =  select_chain.clone();
		let shared_voter_state = shared_voter_state.clone();
		
		let subscription_executor = sc_rpc::SubscriptionTaskExecutor::new(task_manager.spawn_handle());
		let justification_stream = grandpa_link.justification_stream();
		let shared_authority_set = grandpa_link.shared_authority_set().clone();	
		let finality_proof_provider = sc_finality_grandpa::FinalityProofProvider::new_for_service(
			backend.clone(),
			Some(shared_authority_set.clone()),
		);

		Box::new(move |deny_unsafe, _| {
			let deps = edgeware_rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				graph: pool.pool().clone(),
				deny_unsafe,
				is_authority,
				network: network.clone(),
				filter_pool: filter_pool.clone(),
				ethapi_cmd: ethapi_cmd.clone(),
				// command_sink: None,
				frontier_backend: frontier_backend.clone(),
				backend: backend.clone(),
				max_past_logs,
				// transaction_converter,
				select_chain: select_chain.clone(),
				grandpa_deps: edgeware_rpc::GrandpaDeps {
					shared_voter_state: shared_voter_state.clone(),
					shared_authority_set: shared_authority_set.clone(),
					justification_stream: justification_stream.clone(),
					subscription_executor: subscription_executor.clone(),
					finality_provider: finality_proof_provider.clone(),
				},
				enable_dev_signer,
				// debug_requester: spawned_requesters.debug.clone(),
				// trace_filter_requester: spawned_requesters.trace.clone(),
				// trace_filter_max_count: rpc_config.ethapi_trace_max_count,
			};
			#[allow(unused_mut)]
			let mut io = edgeware_rpc::create_full(deps, subscription_task_executor.clone());
			// if ethapi_cmd.contains(&EthApiCmd::Debug) || ethapi_cmd.contains(&EthApiCmd::Trace) {
			// 	rpc::tracing::extend_with_tracing(
			// 		client.clone(),
			// 		tracing_requesters.clone(),
			// 		rpc_config.ethapi_trace_max_count,
			// 		&mut io,
			// 	);
			// }
			Ok(io)
		})
	};

	let local_role=config.role.clone();

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		backend: backend.clone(),
		client: client.clone(),
		keystore: keystore_container.sync_keystore(),
		network: network.clone(),
		rpc_extensions_builder,
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		on_demand: None,
		remote_blockchain: None,
		system_rpc_tx,
		telemetry: telemetry.as_mut(),
	})?;

	let backoff_authoring_blocks: Option<()> = None;

	if let sc_service::config::Role::Authority { .. } = &role {
		let proposer_factory = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let can_author_with = sp_consensus::CanAuthorWithNativeVersion::new(client.executor().clone());
		let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
		let raw_slot_duration = slot_duration.slot_duration();

		let aura =
			sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _, _>(
				StartAuraParams {
					slot_duration,
					client: client.clone(),
					select_chain,
					block_import,
					proposer_factory,
					create_inherent_data_providers: move |_, ()| async move {
						let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

						let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
							*timestamp,
							raw_slot_duration,
						);

						let fee = pallet_dynamic_fee::InherentDataProvider(target_gas_price);

						Ok((timestamp, slot, fee))
					},
					force_authoring,
					backoff_authoring_blocks,
					keystore: keystore_container.sync_keystore(),
					can_author_with,
					sync_oracle: network.clone(),
					justification_sync_link: network.clone(),
					block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
					max_block_proposal_slot_portion: None,
					telemetry: telemetry.as_ref().map(|x| x.handle()),
				},
			)?;

		// the AURA authoring task is considered essential, i.e. if it
		// fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("aura-proposer", aura);
	}

	// Spawn authority discovery module.
	if role.is_authority() {
		let authority_discovery_role = sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore());
		let dht_event_stream = network.event_stream("authority-discovery").filter_map(|e| async move {
			match e {
				Event::Dht(e) => Some(e),
				_ => None,
			}
		});
		let (authority_discovery_worker, _service) = sc_authority_discovery::new_worker_and_service(
			client.clone(),
			network.clone(),
			Box::pin(dht_event_stream),
			authority_discovery_role,
			prometheus_registry.clone(),
		);

		task_manager
			.spawn_handle()
			.spawn("authority-discovery-worker", authority_discovery_worker.run());
	}

	// if the node isn't actively participating in consensus then it doesn't
	// need a keystore, regardless of which protocol we use below.
	let keystore = if role.is_authority() {
		Some(keystore_container.sync_keystore())
	} else {
		None
	};

	let config = sc_finality_grandpa::Config {
		// FIXME #1578 make this available through chainspec
		gossip_duration: Duration::from_millis(333),
		justification_period: 512,
		name: Some(name),
		observer_enabled: false,
		keystore,
		local_role: local_role,
		telemetry: telemetry.as_ref().map(|x| x.handle()),
	};

	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_config = sc_finality_grandpa::GrandpaParams {
			config,
			link: grandpa_link,
			network: network.clone(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			voting_rule: sc_finality_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry,
			shared_voter_state,
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("grandpa-voter", sc_finality_grandpa::run_grandpa_voter(grandpa_config)?);
	}

	network_starter.start_network();
	Ok(NewFullBase {
		task_manager,
		client,
		network,
		transaction_pool,
	})
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration, cli: &Cli) -> Result<TaskManager, ServiceError> {
	new_full_base(config, cli).map(|NewFullBase { task_manager, .. }| task_manager)
}

pub fn new_light_base(
	mut config: Configuration,
) -> Result<TaskManager, ServiceError> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
	);

	let (client, backend, keystore_container, mut task_manager, on_demand) =
		sc_service::new_light_parts::<Block, RuntimeApi, _>(
			&config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;

	let mut telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", worker.run());
		telemetry
	});

	config
		.network
		.extra_sets
		.push(sc_finality_grandpa::grandpa_peers_set_config());

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = Arc::new(sc_transaction_pool::BasicPool::new_light(
		config.transaction_pool.clone(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
		on_demand.clone(),
	));

	let (grandpa_block_import, grandpa_link) = sc_finality_grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	let slot_duration = sc_consensus_aura::slot_duration(&*client)?.slot_duration();

	let import_queue = sc_consensus_aura::import_queue::<sp_consensus_aura::ed25519::AuthorityPair, _, _, _, _, _, _>(
		ImportQueueParams {
			block_import: grandpa_block_import.clone(),
			justification_import: Some(Box::new(grandpa_block_import.clone())),
			client: client.clone(),
			create_inherent_data_providers: move |_, ()| async move {
				let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

				let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_duration(
					*timestamp,
					slot_duration,
				);

				Ok((timestamp, slot))
			},
			spawner: &task_manager.spawn_essential_handle(),
			can_author_with: sp_consensus::NeverCanAuthor,
			registry: config.prometheus_registry(),
			check_for_equivocation: Default::default(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		},
	)?;

	let warp_sync = Arc::new(sc_finality_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		grandpa_link.shared_authority_set().clone(),
	));

	let (network, system_rpc_tx, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			on_demand: Some(on_demand.clone()),
			block_announce_validator_builder: None,
			warp_sync: Some(warp_sync),
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}
	let enable_grandpa = !config.disable_grandpa;
	if enable_grandpa {
		let name = config.network.node_name.clone();

		let config = sc_finality_grandpa::Config {
			gossip_duration: std::time::Duration::from_millis(333),
			justification_period: 512,
			name: Some(name),
			observer_enabled: false,
			keystore: None,
			local_role: config.role.clone(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		task_manager.spawn_handle().spawn_blocking(
			"grandpa-observer",
			sc_finality_grandpa::run_grandpa_observer(config, grandpa_link, network.clone())?,
		);
	}

	sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		remote_blockchain: Some(backend.remote_blockchain()),
		transaction_pool,
		task_manager: &mut task_manager,
		on_demand: Some(on_demand),
		rpc_extensions_builder: Box::new(|_, _| Ok(())),
		config,
		client,
		keystore: keystore_container.sync_keystore(),
		backend,
		network,
		system_rpc_tx,
		telemetry: telemetry.as_mut(),
	})?;

	network_starter.start_network();

	// let light_deps = edgeware_rpc::LightDeps {
	// 	remote_blockchain: backend.remote_blockchain(),
	// 	fetcher: on_demand.clone(),
	// 	client: client.clone(),
	// 	pool: transaction_pool.clone(),
	// };

	// let rpc_extensions = edgeware_rpc::create_light(light_deps);

	// let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
	// 	on_demand: Some(on_demand),
	// 	remote_blockchain: Some(backend.remote_blockchain()),
	// 	rpc_extensions_builder: Box::new(sc_service::NoopRpcExtensionBuilder(rpc_extensions)),
	// 	client: client.clone(),
	// 	transaction_pool: transaction_pool.clone(),
	// 	keystore: keystore_container.sync_keystore(),
	// 	config,
	// 	backend,
	// 	system_rpc_tx,
	// 	network: network.clone(),
	// 	task_manager: &mut task_manager,
	// 	telemetry: telemetry.as_mut(),
	// })?;

	Ok(task_manager)
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
	new_light_base(config)//.map(|(task_manager, ..)| task_manager)
}
