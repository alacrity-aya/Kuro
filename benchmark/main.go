package main

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"kuro-test/bpf"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	nsName    = "ns_client"
	ifaceName = "veth_c"
)

func main() {
	// 1. 锁定 OS 线程，因为 setns 是线程级别的操作
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf(">>> Switching to namespace: %s", nsName)

	// 保存当前的 NS 以便（理论上）恢复，虽然这里进程退出就无所谓了
	origns, _ := netns.Get()
	defer origns.Close()

	// 获取目标 NS 的句柄
	nsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		log.Fatalf("Error getting NS %s: %v", nsName, err)
	}
	defer nsHandle.Close()

	// 2. 切换当前线程到 ns_client
	if err := netns.Set(nsHandle); err != nil {
		log.Fatalf("Error switching to NS: %v", err)
	}

	// ---------------------------------------------------------
	// 从现在开始，所有网络操作都在 ns_client 内部进行
	// ---------------------------------------------------------

	log.Println(">>> Loading eBPF objects...")
	objs := bpf.TcObjects{}
	if err := bpf.LoadTcObjects(&objs, nil); err != nil {
		log.Fatalf("Load objects failed: %v", err)
	}
	defer objs.Close()

	// 获取网卡对象
	linkObj, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Cannot find link %s in NS: %v", ifaceName, err)
	}

	// 3. 创建 clsact qdisc (eBPF 挂载点)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkObj.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	// 如果已存在则忽略错误，或者先删除
	netlink.QdiscAdd(qdisc)

	// 4. 挂载 BPF 到 Egress
	log.Println(">>> Attaching BPF to Egress...")
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkObj.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  0x0003, // ETH_P_ALL
			Priority:  1,
		},
		Fd:           objs.SimpleEdt.FD(),
		Name:         "simple_edt",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("Filter add failed: %v", err)
	}

	log.Println(">>> eBPF Attached! Press Ctrl+C to exit and detach.")

	// 5. 阻塞等待信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println(">>> Detaching...")
	netlink.FilterDel(filter)
}
