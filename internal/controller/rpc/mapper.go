package rpc

import (
	pb "kuro/api/proto/v1"
	"kuro/internal/domain"
)

// =============================================================
// Domain -> Proto (Controller sends commands to Agent)
// =============================================================

func ToProtoCommand(cmd domain.ControllerCommand) *pb.ControllerCmd {
	pbCmd := &pb.ControllerCmd{
		CommandId: cmd.ID,
	}

	switch p := cmd.Payload.(type) {
	case domain.LinkPolicy:
		pbPolicy := &pb.LinkPolicy{
			BandwidthBps:      p.BandwidthBps,
			BaseLatencyNs:     p.BaseLatencyNs,
			JitterNs:          p.JitterNs,
			CorruptionRatePpm: p.CorruptionRatePpm,
			QueueDepthNs:      p.QueueDepthNs,
		}
		// Handle Delete Case (nil policy in proto)
		if p.IsDelete {
			pbPolicy = nil
		}
		pbCmd.Payload = &pb.ControllerCmd_ApplyLinkPolicy{
			ApplyLinkPolicy: &pb.ApplyLinkPolicy{
				SrcIp:  p.SrcIP,
				DstIp:  p.DstIP,
				Policy: pbPolicy,
			},
		}

	case domain.PodPolicy:
		apply := &pb.ApplyPodPolicy{
			PodName:   p.PodName,
			Namespace: p.Namespace,
		}
		if p.SimRate != nil {
			apply.SimRate = &pb.RateLimit{
				UploadBps:   p.SimRate.UploadBps,
				DownloadBps: p.SimRate.DownloadBps,
			}
		}
		if p.SysRate != nil {
			apply.SysRate = &pb.RateLimit{
				UploadBps:   p.SysRate.UploadBps,
				DownloadBps: p.SysRate.DownloadBps,
			}
		}
		pbCmd.Payload = &pb.ControllerCmd_ApplyPolicy{
			ApplyPolicy: apply,
		}

	case domain.NodePolicy:
		pbCmd.Payload = &pb.ControllerCmd_ApplyNodePolicy{
			ApplyNodePolicy: &pb.ApplyNodePolicy{
				IngressLimitBps:   p.IngressLimitBps,
				IngressBurstBytes: p.IngressBurstBytes,
			},
		}

	case domain.ProbeTask:
		var pbType pb.ProbeType
		switch p.Type {
		case domain.ProbeTypeSIM:
			pbType = pb.ProbeType_SIM
		case domain.ProbeTypeSYS:
			pbType = pb.ProbeType_SYS
		}
		pbCmd.Payload = &pb.ControllerCmd_ApplyProbeTask{
			ApplyProbeTask: &pb.ApplyProbeTask{
				TaskId:          p.TaskID,
				SrcPod:          p.SrcPod,
				SrcIp:           p.SrcIP,
				DstPod:          p.DstPod,
				DstIp:           p.DstIP,
				Type:            pbType,
				IntervalSeconds: p.IntervalSeconds,
				TargetPort:      p.TargetPort,
			},
		}

	case domain.ProbeTaskRemoval:
		pbCmd.Payload = &pb.ControllerCmd_RemoveProbeTask{
			RemoveProbeTask: &pb.RemoveProbeTask{
				TaskId: p.TaskID,
			},
		}
	}

	return pbCmd
}

// =============================================================
// Proto -> Domain (Controller receives reports from Agent)
// =============================================================

func FromProtoHeartbeat(hb *pb.Heartbeat) domain.Heartbeat {
	if hb == nil {
		return domain.Heartbeat{}
	}
	return domain.Heartbeat{
		NodeName:        hb.NodeName,
		NodeIP:          hb.NodeIp,
		ManagedPodCount: int(hb.ManagedPodCount),
	}
}

func FromProtoPodEvent(e *pb.PodLifecycleEvent) domain.PodEvent {
	if e == nil {
		return domain.PodEvent{}
	}
	var typ domain.EventType
	switch e.Type {
	case pb.PodLifecycleEvent_ADDED:
		typ = domain.EventAdd
	case pb.PodLifecycleEvent_MODIFIED:
		typ = domain.EventModify
	case pb.PodLifecycleEvent_DELETED:
		typ = domain.EventDelete
	}
	return domain.PodEvent{
		Type:        typ,
		PodName:     e.PodName,
		Namespace:   e.Namespace,
		PodIP:       e.PodIp,
		ContainerID: e.ContainerId,
		HostIfIndex: e.HostIfindex,
	}
}

func FromProtoAck(ack *pb.CommandAck) domain.CommandAck {
	if ack == nil {
		return domain.CommandAck{}
	}
	return domain.CommandAck{
		CommandID: ack.CommandId,
		Success:   ack.Success,
		Message:   ack.Message,
	}
}
