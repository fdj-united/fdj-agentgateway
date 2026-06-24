use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use agent_core::prelude::*;
use agent_core::{drain, metrics, readiness, signal};
use prometheus_client::registry::Registry;
use tokio::task::JoinSet;

use crate::control::caclient;
use crate::telemetry::trc;
use crate::{Config, ProxyInputs, client, mcp, proxy, state_manager};

pub async fn run(config: Arc<Config>) -> anyhow::Result<Bound> {
	let (data_plane_handle, data_plane_pool) = new_data_plane_pool(config.num_worker_threads);

	// Initialize OpenTelemetry resource defaults from gateway + proxy metadata
	trc::set_resource_defaults_from_config(config.as_ref());

	let shutdown = signal::Shutdown::new();
	// Setup a drain channel. drain_tx is used to trigger a drain, which will complete
	// once all drain_rx handlers are dropped.
	// Any component which wants time to gracefully exit should take in a drain_rx clone,
	// await drain_rx.signaled(), then cleanup.
	// Note: there is still a hard timeout if the draining takes too long
	let (drain_tx, drain_rx) = drain::new();

	let ready = readiness::Ready::new();
	let state_mgr_task = ready.register_task("state manager");
	let proxy_task = ready.register_task("agentgateway");

	let readiness_server = crate::management::readiness_server::Server::new(
		config.readiness_addr,
		drain_rx.clone(),
		ready.clone(),
	)
	.await
	.context("readiness server starts")?;
	// Run the readiness server in the data plane worker pool.
	data_plane_pool.send(DataPlaneTask {
		block_shutdown: false,
		fut: Box::pin(async move {
			readiness_server.spawn();
			Ok(())
		}),
	})?;

	let mut registry = Registry::default();
	let sub_registry = metrics::sub_registry(&mut registry);
	let xds_metrics = agent_xds::Metrics::new(sub_registry);
	agent_core::metrics::TokioCollector::register(sub_registry, &data_plane_handle);

	// TODO: use for XDS
	let control_client = client::Client::new(&config.dns, None, config.backend.clone(), None);
	let ca = if let Some(cfg) = &config.ca {
		Some(Arc::new(caclient::CaClient::new(
			control_client.clone(),
			cfg.clone(),
		)?))
	} else {
		None
	};
	let pool = ca
		.clone()
		.map(|ca| agent_hbone::pool::WorkloadHBONEPool::new(config.hbone.clone(), ca));
	// Build metrics and then the upstream client with metrics wired in
	let sub_registry = metrics::sub_registry(&mut registry);
	let metrics_handle = Arc::new(crate::metrics::Metrics::new(
		sub_registry,
		config.metrics.excluded_metrics.clone(),
	));
	let client = client::Client::new(
		&config.dns,
		pool,
		config.backend.clone(),
		Some(metrics_handle.clone()),
	);

	let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
	let state_mgr =
		state_manager::StateManager::new(config.clone(), control_client.clone(), xds_metrics, xds_tx)
			.await?;
	let stores = state_mgr.stores();

	let mut xds_rx_for_task = xds_rx.clone();
	tokio::spawn(async move {
		// When we get the initial XDS state, unblock readiness
		let _ = xds_rx_for_task.changed().await;
		std::mem::drop(state_mgr_task);
	});
	// Run the XDS state manager in the current tokio worker pool.
	tokio::spawn(state_mgr.run());

	#[allow(unused_mut)]
	let mut admin_server = crate::management::admin::Service::new(
		config.clone(),
		stores.clone(),
		shutdown.trigger(),
		drain_rx.clone(),
		data_plane_handle.clone(),
	)
	.await
	.context("admin server starts")?;
	#[cfg(feature = "ui")]
	admin_server.set_admin_handler(Arc::new(crate::ui::UiHandler::new(config.clone())));
	#[cfg(feature = "ui")]
	info!("serving UI at http://{}/ui", config.admin_addr);

	// Externalised MCP session state (confirmations + rate limits). Backed by Redis
	// when REDIS_URL is set (required for safe multi-pod scaling), in-memory otherwise.
	let mcp_state_store = build_mcp_state_store().await?;

	let pi = ProxyInputs {
		cfg: config.clone(),
		stores: stores.clone(),
		metrics: metrics_handle.clone(),
		upstream: client.clone(),
		ca,

		mcp_state: mcp::App::new(
			stores.clone(),
			config.session_encoder.clone(),
			mcp_state_store,
		),
	};

	let gw = proxy::Gateway::new(Arc::new(pi), drain_rx.clone());

	// Run the agentgateway in the data plane worker pool.
	let mut xds_rx_for_proxy = xds_rx.clone();
	data_plane_pool.send(DataPlaneTask {
		block_shutdown: true,
		fut: Box::pin(async move {
			// Wait for XDS to be ready
			let _ = xds_rx_for_proxy.changed().await;
			// Now run
			gw.run().in_current_span().await;
			Ok(())
		}),
	})?;

	drop(proxy_task);

	// Run the admin server in the current tokio worker pool.
	admin_server.spawn();

	// Create and start the metrics server.
	let metrics_server =
		crate::management::metrics_server::Server::new(config.stats_addr, drain_rx.clone(), registry)
			.await
			.context("stats server starts")?;
	// Run the metrics sever in the current tokio worker pool.
	metrics_server.spawn();
	Ok(Bound {
		drain_tx,
		shutdown,
		stores,
		ready,
	})
}

/// Construct the MCP state store from the environment.
///
/// * `REDIS_URL` — when set (and non-empty), use the shared Redis backend so the
///   gateway can run with `replicas > 1`. Unset → in-memory (per-pod) backend.
/// * `STATE_STORE_FAILURE_MODE` — `failOpen` or `failClosed` (default). Governs
///   what the Redis backend does on a backend error at request time, and whether
///   a failed connection at startup is fatal (`failClosed`) or degrades to the
///   in-memory backend (`failOpen`).
async fn build_mcp_state_store() -> anyhow::Result<Arc<dyn crate::state_store::StateStore>> {
	use crate::mcp::FailureMode;
	use crate::state_store::{InMemoryStore, RedisStore};

	let failure_mode = match std::env::var("STATE_STORE_FAILURE_MODE")
		.unwrap_or_default()
		.to_ascii_lowercase()
		.as_str()
	{
		"failopen" | "fail_open" => FailureMode::FailOpen,
		_ => FailureMode::FailClosed,
	};

	match std::env::var("REDIS_URL") {
		Ok(url) if !url.trim().is_empty() => match RedisStore::connect(&url, failure_mode).await {
			Ok(store) => {
				info!("state_store: Redis backend connected (failure_mode={failure_mode:?})");
				Ok(Arc::new(store))
			},
			Err(e) => match failure_mode {
				// Fail fast: refuse to start silently degraded to per-pod state.
				FailureMode::FailClosed => Err(e.context(
					"REDIS_URL is set but Redis is unreachable and STATE_STORE_FAILURE_MODE=failClosed",
				)),
				// Tolerate: degrade to in-memory rather than block startup.
				FailureMode::FailOpen => {
					warn!(
						"state_store: Redis connect failed, falling back to in-memory (failure_mode=FailOpen): {e}"
					);
					Ok(Arc::new(InMemoryStore::new()))
				},
			},
		},
		_ => {
			info!("state_store: using in-memory backend (REDIS_URL not set)");
			Ok(Arc::new(InMemoryStore::new()))
		},
	}
}

pub struct Bound {
	pub shutdown: signal::Shutdown,
	drain_tx: drain::DrainTrigger,
	ready: readiness::Ready,
	stores: crate::store::Stores,
}

impl Bound {
	pub fn readiness(&self) -> readiness::Ready {
		self.ready.clone()
	}

	pub async fn wait_termination(self) -> anyhow::Result<()> {
		// Wait for a signal to shutdown from explicit admin shutdown or signal
		self.shutdown.wait().await;

		let sdp = {
			let b = self.stores.binds.read();
			b.all_shutdown_policies()
		};
		for p in sdp {
			p();
		}

		// Start a drain; this will attempt to end all connections
		// or itself be interrupted by a stronger TERM signal, whichever comes first.
		self
			.drain_tx
			.start_drain_and_wait(drain::DrainMode::Graceful)
			.await;

		Ok(())
	}
}

struct DataPlaneTask {
	block_shutdown: bool,
	fut: Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + Sync + 'static>>,
}

fn new_data_plane_pool(
	num_worker_threads: usize,
) -> (tokio::runtime::Handle, mpsc::Sender<DataPlaneTask>) {
	let (tx, rx) = mpsc::channel();
	let (tx_handle, rx_handle) = mpsc::channel();

	let span = tracing::span::Span::current();
	thread::spawn(move || {
		let _span = span.enter();
		let runtime = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(num_worker_threads)
			.thread_name_fn(|| {
				static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
				let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
				format!("agentgateway-{id}")
			})
			.enable_all()
			.build()
			.unwrap();
		tx_handle.send(runtime.handle().clone()).unwrap();
		runtime.block_on(
			async move {
				let mut join_set = JoinSet::new();

				// Spawn tasks as they're received, until all tasks are spawned.
				let task_iter: mpsc::Iter<DataPlaneTask> = rx.iter();
				for task in task_iter {
					if task.block_shutdown {
						// We'll block shutdown on this task.
						join_set.spawn(task.fut);
					} else {
						// We won't block shutdown of this task. Just spawn and forget.
						tokio::spawn(task.fut);
					}
				}

				while let Some(join_result) = join_set.join_next().await {
					match join_result {
						Ok(result) => {
							if let Err(e) = result {
								warn!("data plane task failed: {e}");
							}
						},
						Err(e) => warn!("failed joining data plane task: {e}"),
					}
				}
			}
			.in_current_span(),
		);
	});

	let handle = rx_handle.recv().unwrap();
	(handle, tx)
}
