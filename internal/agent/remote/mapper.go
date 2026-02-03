package remote

import (
	pb "kuro/api/proto/v1"
	"kuro/internal/domain"
)

// =============================================================
// Domain -> Proto
// =============================================================

func ToProtoHeartbeat(h domain.Heartbeat) *pb.Heartbeat {
	return &pb.Heartbeat{
		NodeName:        h.NodeName,
		NodeIp:          h.NodeIP,
		ManagedPodCount: int32(h.ManagedPodCount),
	}
}

func ToProtoPodEvent(e domain.PodEvent) *pb.PodLifecycleEvent {
	var evtType pb.PodLifecycleEvent_EventType
	switch e.Type {
	case domain.EventAdd:
		evtType = pb.PodLifecycleEvent_ADDED
	case domain.EventModify:
		evtType = pb.PodLifecycleEvent_MODIFIED
	case domain.EventDelete:
		evtType = pb.PodLifecycleEvent_DELETED
	}

	return &pb.PodLifecycleEvent{
		Type:        evtType,
		PodName:     e.PodName,
		Namespace:   e.Namespace,
		PodIp:       e.PodIP,
		ContainerId: e.ContainerID,
		HostIfindex: e.HostIfIndex,
	}
}

func ToProtoAck(ack domain.CommandAck) *pb.CommandAck {
	return &pb.CommandAck{
		CommandId: ack.CommandID,
		Success:   ack.Success,
		Message:   ack.Message,
	}
}

// =============================================================
// Proto -> Domain
// =============================================================

func FromProtoLinkPolicy(p *pb.ApplyLinkPolicy) domain.LinkPolicy {
	policy := domain.LinkPolicy{
		SrcIP: p.SrcIp,
		DstIP: p.DstIp,
	}

	if p.Policy == nil {
		policy.IsDelete = true
	} else {
		policy.BandwidthBps = p.Policy.BandwidthBps
		policy.BaseLatencyNs = p.Policy.BaseLatencyNs
		policy.JitterNs = p.Policy.JitterNs
		policy.CorruptionRatePpm = p.Policy.CorruptionRatePpm
		policy.QueueDepthNs = p.Policy.QueueDepthNs
		policy.IsDelete = false
	}
	return policy
}

func FromProtoPodPolicy(p *pb.ApplyPodPolicy) domain.PodPolicy {
	policy := domain.PodPolicy{
		PodName:   p.PodName,
		Namespace: p.Namespace,
	}

	if p.SimRate != nil {
		policy.SimRate = &domain.RateLimit{
			UploadBps:   p.SimRate.UploadBps,
			DownloadBps: p.SimRate.DownloadBps,
		}
	}
	if p.SysRate != nil {
		policy.SysRate = &domain.RateLimit{
			UploadBps:   p.SysRate.UploadBps,
			DownloadBps: p.SysRate.DownloadBps,
		}
	}
	return policy
}

func FromProtoNodePolicy(p *pb.ApplyNodePolicy) domain.NodePolicy {
	return domain.NodePolicy{
		IngressLimitBps:   p.IngressLimitBps,
		IngressBurstBytes: p.IngressBurstBytes,
	}
}
