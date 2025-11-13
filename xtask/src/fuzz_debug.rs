use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use firewood::merkle::Merkle;
use firewood_storage::{
    hash_preimage, noop_storage_metrics, Child, Committed, HashedNodeRef, ImmutableProposal,
    MemStore, Node, NodeStore, Path, SharedNode,
};
use hex::encode;

const DEFAULT_ITERATION: usize = 106;
const DEFAULT_ITEMS_PER_ITERATION: usize = 100;
const DEFAULT_VALUE_LEN: usize = 256;

#[derive(Debug, Clone)]
struct Config {
    iteration: usize,
    items_per_iteration: usize,
    seed: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            iteration: DEFAULT_ITERATION,
            items_per_iteration: DEFAULT_ITEMS_PER_ITERATION,
            seed: Some(42),
        }
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut iter = args.iter();
    let Some(subcommand) = iter.next() else {
        bail!("fuzz-debug expects a subcommand (dump|inspect)");
    };

    let mut config = Config::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--iteration" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--iteration requires a value"))?;
                config.iteration = value.parse::<usize>().context("parse --iteration")?;
            }
            "--items" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--items requires a value"))?;
                config.items_per_iteration = value.parse::<usize>().context("parse --items")?;
            }
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("--seed requires a value"))?;
                if value.eq_ignore_ascii_case("env") {
                    config.seed = None;
                } else {
                    config.seed = Some(value.parse::<u64>().context("parse --seed")?);
                }
            }
            other => bail!("unknown fuzz-debug flag: {other}"),
        }
    }

    match subcommand.as_str() {
        "dump" => dump_dataset(&config),
        "inspect" => inspect_roots(&config),
        other => bail!("unknown fuzz-debug subcommand: {other}"),
    }
}

fn dump_dataset(config: &Config) -> Result<()> {
    let dataset = iteration_dataset(config);
    println!("ITER {}", config.iteration);
    for (index, (key, value)) in dataset.iter().enumerate() {
        println!("{}:{}:{}", index, encode(key), encode(value));
    }
    Ok(())
}

fn inspect_roots(config: &Config) -> Result<()> {
    let dataset = iteration_dataset(config);

    let actual_merkle = init_merkle(&dataset).context("build actual merkle")?;

    let mut deduped: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (key, value) in &dataset {
        deduped.insert(key.clone(), value.clone());
    }
    let expected_items: Vec<(Vec<u8>, Vec<u8>)> = deduped.into_iter().collect();
    let expected_merkle = init_merkle(&expected_items).context("build expected merkle")?;

    let actual_root = actual_merkle
        .try_root()
        .context("load actual root")?
        .expect("actual root");
    let expected_root = expected_merkle
        .try_root()
        .context("load expected root")?
        .expect("expected root");

    let actual_preimage = hash_preimage(
        HashedNodeRef::try_from(actual_root.deref()).context("actual root hashable")?,
        &Path::new(),
    );
    println!("actual root preimage={}", encode(actual_preimage.as_ref()));

    let mut actual_lines = Vec::new();
    describe_node(
        actual_merkle.nodestore_for_debug(),
        actual_root,
        &Path::new(),
        &mut actual_lines,
    )
    .context("describe actual trie")?;
    println!("actual trie:");
    for line in &actual_lines {
        println!("  {line}");
    }

    let expected_preimage = hash_preimage(
        HashedNodeRef::try_from(expected_root.deref()).context("expected root hashable")?,
        &Path::new(),
    );
    println!(
        "expected root preimage={}",
        encode(expected_preimage.as_ref())
    );

    let mut expected_lines = Vec::new();
    describe_node(
        expected_merkle.nodestore_for_debug(),
        expected_root,
        &Path::new(),
        &mut expected_lines,
    )
    .context("describe expected trie")?;
    println!("expected trie:");
    for line in &expected_lines {
        println!("  {line}");
    }

    Ok(())
}

fn iteration_dataset(config: &Config) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rng = firewood_storage::SeededRng::from_option(config.seed);
    let max_len0 = 8;
    let max_len1 = 4;
    let keygen = || {
        let (len0, len1): (usize, usize) = {
            (
                rng.random_range(1..=max_len0),
                rng.random_range(1..=max_len1),
            )
        };
        (0..len0)
            .map(|_| rng.random_range(0..2))
            .chain((0..len1).map(|_| rng.random()))
            .collect::<Vec<u8>>()
    };

    for iter in 0..=config.iteration {
        let mut items = Vec::with_capacity(config.items_per_iteration);
        for _ in 0..config.items_per_iteration {
            let value: Vec<u8> = (0..DEFAULT_VALUE_LEN).map(|_| rng.random()).collect();
            items.push((keygen(), value));
        }
        if iter == config.iteration {
            return items;
        }
    }

    unreachable!("iteration dataset generation must return");
}

fn init_merkle(items: &[(Vec<u8>, Vec<u8>)]) -> Result<Merkle<NodeStore<Committed, MemStore>>> {
    let memstore = Arc::new(MemStore::new(Vec::with_capacity(64 * 1024)));
    let base_store = NodeStore::new_empty_committed(memstore, noop_storage_metrics())
        .context("create base nodestore")?;
    let base = Merkle::from(base_store);
    let mut proposal = base.fork().context("fork base merkle")?;

    for (key, value) in items.iter() {
        proposal
            .insert(key, value.clone().into_boxed_slice())
            .with_context(|| format!("insert key {:?}", key))?;
    }

    let hashed = proposal.hash();
    into_committed(hashed, base.nodestore_for_debug())
}

fn into_committed(
    merkle: Merkle<NodeStore<Arc<ImmutableProposal>, MemStore>>,
    parent: &NodeStore<Committed, MemStore>,
) -> Result<Merkle<NodeStore<Committed, MemStore>>> {
    let mut store = merkle.into_inner_for_debug();
    store.flush_freelist().context("flush freelist")?;
    store.flush_header().context("flush header")?;
    let mut committed = store.as_committed(parent);
    committed.flush_nodes().context("flush nodes")?;
    Ok(committed.into())
}

fn describe_node(
    store: &NodeStore<Committed, MemStore>,
    node: SharedNode,
    prefix: &Path,
    lines: &mut Vec<String>,
) -> Result<()> {
    match node.deref() {
        Node::Branch(branch) => {
            let mut full_path = prefix.clone();
            full_path.extend(branch.partial_path.iter().copied());
            let mut child_summaries = Vec::new();
            for (idx, child) in branch.children.iter().enumerate() {
                let Some(child) = child else { continue };
                let hash = match child {
                    Child::Node(_) => None,
                    Child::AddressWithHash(_, hash) => Some(hash),
                    Child::MaybePersisted(_, hash) => Some(hash),
                };
                let summary = if let Some(hash) = hash {
                    format!("{idx}:{}", encode(&hash.as_ref()[..4]))
                } else {
                    format!("{idx}:<pending>")
                };
                child_summaries.push(summary);
            }
            lines.push(format!(
                "branch path={} value={} children=[{}]",
                encode(full_path.as_ref()),
                branch.value.as_ref().map(|v| v.len()).unwrap_or(0),
                child_summaries.join(", "),
            ));

            for (idx, child) in branch.children.iter().enumerate() {
                let Some(child) = child else { continue };
                let child_node = match child {
                    Child::Node(inner) => SharedNode::new(inner.clone()),
                    Child::AddressWithHash(address, _) => store
                        .read_node((*address).into())
                        .context("load persisted child")?,
                    Child::MaybePersisted(maybe, _) => maybe
                        .as_shared_node(store)
                        .context("load maybe persisted child")?,
                };
                let mut child_prefix = full_path.clone();
                child_prefix.extend([idx as u8]);
                describe_node(store, child_node, &child_prefix, lines)?;
            }
        }
        Node::Leaf(leaf) => {
            let mut full_path = prefix.clone();
            full_path.extend(leaf.partial_path.iter().copied());
            lines.push(format!(
                "leaf path={} value_len={}",
                encode(full_path.as_ref()),
                leaf.value.len(),
            ));
        }
    }

    Ok(())
}
