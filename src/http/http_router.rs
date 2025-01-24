use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
struct RouterNode {
    children: HashMap<String, RouterNode>,
    is_wildcard: bool,
    is_endpoint: bool,
    handler_index: Option<usize>,
}

impl RouterNode {
    fn new() -> Self {
        RouterNode {
            children: HashMap::new(),
            is_wildcard: false,
            is_endpoint: false,
            handler_index: None,
        }
    }

    fn insert(&mut self, path: &str, handler_index: usize) {
        if path.is_empty() {
            self.is_endpoint = true;
            self.handler_index = Some(handler_index);
            return;
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current = self;

        for segment in segments {
            let is_wildcard = segment == "*";
            let entry = current
                .children
                .entry(segment.to_string())
                .or_insert_with(|| {
                    let mut node = RouterNode::new();
                    node.is_wildcard = is_wildcard;
                    node
                });
            current = entry;
        }

        current.is_endpoint = true;
        current.handler_index = Some(handler_index);
    }

    fn find(&self, path: &str) -> Option<usize> {
        if path.is_empty() {
            return if self.is_endpoint {
                self.handler_index
            } else {
                None
            };
        }

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current = self;

        for segment in segments {
            if let Some(child) = current.children.get(segment) {
                current = child;
            } else if let Some(wildcard) = current.children.get("*") {
                current = wildcard;
            } else {
                return None;
            }
        }

        if current.is_endpoint {
            current.handler_index
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct Router {
    root: RouterNode,
    handlers: Arc<Vec<Box<dyn Fn() + Send + Sync + 'static>>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Router {
            root: RouterNode::new(),
            handlers: Arc::new(Vec::new()),
        }
    }

    pub fn add_route<F>(&mut self, path: &str, handler: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let handlers = Arc::get_mut(&mut self.handlers)
            .expect("Cannot modify Router after it has been shared");
        let handler_index = handlers.len();
        handlers.push(Box::new(handler));
        self.root.insert(path, handler_index);
    }

    pub fn route(&self, path: &str) -> Option<()> {
        self.root.find(path).map(|index| (self.handlers[index])())
    }
}
