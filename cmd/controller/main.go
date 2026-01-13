package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alacrity-aya/Kuro/internal/api/v1alpha1"
	"github.com/alacrity-aya/Kuro/internal/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	// [需求1] 初始化 slog
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	// 1. 初始化 Reconcilers
	workloadReconciler := controller.NewWorkloadReconciler(kubeClient, logger)
	topologyReconciler := controller.NewTopologyReconciler(kubeClient, logger)

	// 2. 准备 Factory
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynClient, time.Minute, corev1.NamespaceAll, nil)

	// 3. 注册 ExperimentWorkload 监听
	gvrWorkload := schema.GroupVersionResource{Group: "kuro.io", Version: "v1alpha1", Resource: "experimentworkloads"}
	workloadInformer := factory.ForResource(gvrWorkload).Informer()
	workloadInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			wl := convertToWorkload(u)
			// 使用 slog
			logger.Info("EVENT: ADD Workload", "name", wl.Name)
			if err := workloadReconciler.Reconcile(wl); err != nil {
				logger.Error("Workload Reconcile Failed", "error", err)
			}
		},
		DeleteFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			logger.Info("EVENT: DELETE Workload", "name", u.GetName())
		},
	})

	// 4. [新增] 注册 NetworkTopology 监听
	gvrTopology := schema.GroupVersionResource{Group: "kuro.io", Version: "v1alpha1", Resource: "networktopologies"} // 注意 plural 是 networktopologies
	topoInformer := factory.ForResource(gvrTopology).Informer()
	topoInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			topo := convertToTopology(u)
			logger.Info("EVENT: ADD Topology", "name", topo.Name)
			if err := topologyReconciler.Reconcile(topo); err != nil {
				logger.Error("Topology Reconcile Failed", "error", err)
			}
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	logger.Info("Kuro Controller 正在启动...")
	factory.Start(stopCh)

	<-stopCh
}

// 辅助转换函数
func convertToWorkload(u *unstructured.Unstructured) *v1alpha1.ExperimentWorkload {
	var val v1alpha1.ExperimentWorkload
	data, _ := json.Marshal(u.Object)
	_ = json.Unmarshal(data, &val)
	return &val
}

func convertToTopology(u *unstructured.Unstructured) *v1alpha1.NetworkTopology {
	var val v1alpha1.NetworkTopology
	data, _ := json.Marshal(u.Object)
	_ = json.Unmarshal(data, &val)
	return &val
}
