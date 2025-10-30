use crate::admission::{AdmissionControl, AdmissionError};
use crate::metrics::{gossip_decision_for_snapshot, gossip_rejection, AdmissionMetrics};
use crate::peerstore::ReputationSnapshot;
use crate::topics::GossipTopic;
use crate::vendor::PeerId;
use tracing::{debug, warn};

pub fn evaluate_publish(
    admission: &AdmissionControl,
    #[cfg(feature = "metrics")] metrics: &AdmissionMetrics,
    peer: &PeerId,
    topic: GossipTopic,
) -> Result<ReputationSnapshot, AdmissionError> {
    match admission.can_remote_publish(peer, topic) {
        Ok(snapshot) => {
            #[cfg(feature = "metrics")]
            {
                let decision = gossip_decision_for_snapshot(&snapshot);
                metrics.record_gossip(peer, topic, &decision);
            }
            debug!(
                target: "telemetry.gossip",
                peer = ?peer,
                topic = %topic,
                tier = ?snapshot.tier,
                "gossip_publish_allowed"
            );
            Ok(snapshot)
        }
        Err(err) => {
            let reason = err.to_string();
            #[cfg(feature = "metrics")]
            {
                let decision = gossip_rejection(reason.clone());
                metrics.record_gossip(peer, topic, &decision);
            }
            warn!(
                target: "telemetry.gossip",
                peer = ?peer,
                topic = %topic,
                reason = %reason,
                "gossip_publish_rejected"
            );
            Err(err)
        }
    }
}
