package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"google.golang.org/grpc"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	smv1pb "github.com/ramonberrutti/diy-service-mesh/protogen/apis/sm/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

var _ = informers.NewSharedInformerFactory(nil, 0)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Create a new k8s client
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	factory := informers.NewSharedInformerFactory(clientset, time.Hour)

	serviceInformer := factory.Core().V1().Services()
	endpointInformer := factory.Discovery().V1().EndpointSlices()

	w := &watcher{
		services: make(map[string]*smv1pb.Service),
	}

	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.addService,
		UpdateFunc: w.updateService,
		DeleteFunc: w.deleteService,
	})

	endpointInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.addEndpointSlice,
		UpdateFunc: w.updateEndpointSlice,
		DeleteFunc: w.deleteEndpointSlice,
	})

	stopCh := ctx.Done()

	factory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, serviceInformer.Informer().HasSynced) {
		panic("failed to sync")
	}

	if !cache.WaitForCacheSync(stopCh, endpointInformer.Informer().HasSynced) {
		panic("failed to sync")
	}

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	srv := grpc.NewServer()

	smv1pb.RegisterServiceMeshServiceServer(srv, &serviceMeshServer{
		watcher: w,
	})

	go func() {
		if err := srv.Serve(l); err != nil {
			panic(err)
		}
	}()

	<-ctx.Done()
	srv.GracefulStop()
}

type serviceMeshServer struct {
	smv1pb.UnimplementedServiceMeshServiceServer
	watcher *watcher
}

func (s *serviceMeshServer) GetServices(ctx context.Context, req *smv1pb.GetServicesRequest) (*smv1pb.GetServicesResponse, error) {
	services := s.watcher.getServices(req.Services)
	return &smv1pb.GetServicesResponse{
		Services: services,
	}, nil
}

type watcher struct {
	sync.Mutex

	services map[string]*smv1pb.Service
}

func (w *watcher) getServices(services []string) []*smv1pb.Service {
	w.Lock()
	defer w.Unlock()

	res := make([]*smv1pb.Service, len(services))
	for i, key := range services {
		res[i] = w.services[key]
	}

	return res
}

func (w *watcher) addService(obj any) {
	service := obj.(*corev1.Service)

	key := service.Namespace + "/" + service.Name

	w.Lock()
	defer w.Unlock()
	svc, ok := w.services[key]
	if !ok {
		svc = &smv1pb.Service{
			Name:      service.Name,
			Namespace: service.Namespace,
		}
	}

	svc.Ports = make([]*smv1pb.Service_Port, len(service.Spec.Ports))
	for i, port := range service.Spec.Ports {
		svc.Ports[i] = &smv1pb.Service_Port{
			Name:       port.Name,
			Protocol:   string(port.Protocol),
			Port:       int32(port.Port),
			TargetPort: port.TargetPort.IntVal,
		}
	}
	svc.ClusterIps = service.Spec.ClusterIPs

	w.services[key] = svc
}

func (w *watcher) updateService(oldObj, newObj any) {
	w.addService(newObj)
}

func (w *watcher) deleteService(obj any) {
	service, ok := obj.(*corev1.Service)
	if !ok {
		// The object is of an unexpected type
		return
	}

	key := service.Namespace + "/" + service.Name
	w.Lock()
	defer w.Unlock()
	delete(w.services, key)
}

func (w *watcher) addEndpointSlice(obj any) {
	endpoints := obj.(*discoveryv1.EndpointSlice)

	serviceName, ok := endpoints.Labels[discoveryv1.LabelServiceName]
	if !ok {
		return
	}

	key := endpoints.Namespace + "/" + serviceName

	w.Lock()
	defer w.Unlock()
	svc, ok := w.services[key]
	if !ok {
		svc = &smv1pb.Service{
			Name:      serviceName,
			Namespace: endpoints.Namespace,
		}
	}

	svc.Endpoints = make([]*smv1pb.Service_Endpoint, len(endpoints.Endpoints))
	for i, endpoint := range endpoints.Endpoints {
		// Check if the endpoint is ready
		ready := true
		if endpoint.Conditions.Ready != nil {
			ready = *endpoint.Conditions.Ready
		}
		podName := ""
		if endpoint.TargetRef != nil {
			podName = endpoint.TargetRef.Name
		}

		svc.Endpoints[i] = &smv1pb.Service_Endpoint{
			Addresses: endpoint.Addresses,
			Ready:     ready,
			PodName:   podName,
			// We are ignoring serving and terminating for now
		}
	}

	w.services[key] = svc
}

func (w *watcher) updateEndpointSlice(oldObj, newObj any) {
	w.addEndpointSlice(newObj)
}

func (w *watcher) deleteEndpointSlice(obj any) {
	endpoints, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		// The object is of an unexpected type
		return
	}

	serviceName, ok := endpoints.Labels[discoveryv1.LabelServiceName]
	if !ok {
		return
	}

	key := endpoints.Namespace + "/" + serviceName
	w.Lock()
	defer w.Unlock()
	delete(w.services, key)
}
