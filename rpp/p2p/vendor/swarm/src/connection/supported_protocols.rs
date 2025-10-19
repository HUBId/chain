use std::collections::HashSet;

use crate::{handler::ProtocolsChange, StreamProtocol};

#[derive(Default, Clone, Debug)]
pub struct SupportedProtocols {
    protocols: HashSet<StreamProtocol>,
}

impl SupportedProtocols {
    pub fn on_protocols_change(&mut self, change: ProtocolsChange) -> bool {
        match change {
            ProtocolsChange::Added(added) => {
                let mut changed = false;

                for p in added {
                    changed |= self.protocols.insert(p.clone());
                }

                changed
            }
            ProtocolsChange::Removed(removed) => {
                let mut changed = false;

                for p in removed {
                    changed |= self.protocols.remove(p);
                }

                changed
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &StreamProtocol> {
        self.protocols.iter()
    }
}

