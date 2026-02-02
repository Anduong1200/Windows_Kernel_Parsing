use pyo3.prelude::*;
use std::collections::{HashSet, HashMap, VecDeque};
use std::cmp::{min, max};
use serde::{Deserialize, Serialize};

#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RustNode {
    #[pyo3(get, set)]
    ea: u64,
    #[pyo3(get, set)]
    role: String,
    #[pyo3(get, set)]
    is_error_handler: bool,
    #[pyo3(get, set)]
    has_failfast: bool,
}

#[pymethods]
impl RustNode {
    #[new]
    fn new(ea: u64, role: String, is_error_handler: bool, has_failfast: bool) -> Self {
        RustNode {
            ea,
            role,
            is_error_handler,
            has_failfast,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
struct RustGraph {
    #[pyo3(get, set)]
    anchor: u64,
    nodes: HashMap<u64, RustNode>,
    edges: Vec<(u64, u64, String)>,
    // Adjacency list for fast traversal: Caller -> Vec<Callee>
    adjacency: HashMap<u64, Vec<u64>>,
}

#[pymethods]
impl RustGraph {
    #[new]
    fn new(anchor: u64) -> Self {
        RustGraph {
            anchor,
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
        }
    }

    fn add_node(&mut self, node: RustNode) {
        self.nodes.insert(node.ea, node);
    }

    fn add_edge(&mut self, caller: u64, callee: u64, edge_type: String) {
        self.edges.push((caller, callee, edge_type));
        self.adjacency.entry(caller).or_insert_with(Vec::new).push(callee);
    }

    fn get_node_count(&self) -> usize {
        self.nodes.len()
    }
    
    fn get_edge_count(&self) -> usize {
        self.edges.len()
    }
}

/// Calculate Jaccard Similarity between two sets of strings.
#[pyfunction]
fn calculate_jaccard_similarity(set_a: Vec<String>, set_b: Vec<String>) -> f64 {
    let set_a: HashSet<_> = set_a.into_iter().collect();
    let set_b: HashSet<_> = set_b.into_iter().collect();

    let intersection_count = set_a.intersection(&set_b).count();
    let union_count = set_a.union(&set_b).count();

    if union_count == 0 {
        return 0.0;
    }

    intersection_count as f64 / union_count as f64
}

/// A graph traversal to find connected nodes (BFS).
/// Returns a list of visited node (Function) addresses.
#[pyfunction]
fn bfs_traversal(
    start_node: String, 
    adjacency_list: HashMap<String, Vec<String>>, 
    max_depth: Option<usize>
) -> Vec<String> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let max_depth = max_depth.unwrap_or(usize::MAX);

    visited.insert(start_node.clone());
    queue.push_back((start_node, 0));

    let mut result = Vec::new();

    while let Some((current_node, depth)) = queue.pop_front() {
        result.push(current_node.clone());

        if depth >= max_depth {
            continue;
        }

        if let Some(neighbors) = adjacency_list.get(&current_node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    visited.insert(neighbor.clone());
                    queue.push_back((neighbor.clone(), depth + 1));
                }
            }
        }
    }

    result
}

/// Calculate semantic similarity between two nodes.
#[pyfunction]
fn calculate_node_similarity(node_a: &RustNode, node_b: &RustNode) -> f64 {
    let mut score = 0.0;
    let mut max_score = 0.0;

    // Role Match (High Weight)
    max_score += 5.0;
    if node_a.role == node_b.role {
        score += 5.0;
    }

    // FailFast Match
    max_score += 3.0;
    if node_a.has_failfast == node_b.has_failfast {
        score += 3.0;
    }
    
    // Error Handler Match
    max_score += 3.0;
    if node_a.is_error_handler == node_b.is_error_handler {
        score += 3.0;
    }

    if max_score == 0.0 { 1.0 } else { score / max_score }
}

/// Compare structure of two graphs.
#[pyfunction]
fn compare_structure(graph_a: &RustGraph, graph_b: &RustGraph) -> HashMap<String, f64> {
    let mut result = HashMap::new();
    
    // Node Count Diff
    let count_a = graph_a.nodes.len() as f64;
    let count_b = graph_b.nodes.len() as f64;
    let node_diff = (count_a - count_b).abs();
    
    // Normalize difference (0 = identical, 1 = huge difference)
    let max_nodes = count_a.max(count_b);
    let node_similarity = if max_nodes > 0.0 {
        1.0 - (node_diff / max_nodes)
    } else {
        1.0
    };
    
    result.insert("node_similarity".to_string(), node_similarity);
    
    // Edge Count Diff
    let edge_count_a = graph_a.edges.len() as f64;
    let edge_count_b = graph_b.edges.len() as f64;
    let max_edges = edge_count_a.max(edge_count_b);
    let edge_similarity = if max_edges > 0.0 {
        1.0 - ((edge_count_a - edge_count_b).abs() / max_edges)
    } else {
        1.0
    };
    result.insert("edge_similarity".to_string(), edge_similarity);

    result
}

/// A Python module implemented in Rust.
#[pymodule]
fn logic_flow_native(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RustNode>()?;
    m.add_class::<RustGraph>()?;
    m.add_function(wrap_pyfunction!(calculate_jaccard_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(bfs_traversal, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_node_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(compare_structure, m)?)?;
    Ok(())
}
