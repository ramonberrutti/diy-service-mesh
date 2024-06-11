package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientAuthenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	clientCorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
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

	caCert, caKey, err := createCertificateAuthority(ctx, clientset.CoreV1().Secrets(os.Getenv("POD_NAMESPACE")))
	if err != nil {
		panic(err)
	}

	// Create the shared informer factory with one hour of resync.
	factory := informers.NewSharedInformerFactory(clientset, time.Hour)

	// For now we are going to watch only the services and EndpointSlices
	serviceInformer := factory.Core().V1().Services().Informer()
	endpointInformer := factory.Discovery().V1().EndpointSlices().Informer()

	// Creates our watcher where we are going to process the events and save the services and endpointsslices
	w := &watcher{
		services: make(map[string]*smv1pb.Service),
	}

	// The informer is going to call the methods of the watcher when a event occurs.
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.addService,
		UpdateFunc: w.updateService,
		DeleteFunc: w.deleteService,
	})
	endpointInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.addEndpointSlice,
		UpdateFunc: w.updateEndpointSlice,
		DeleteFunc: w.deleteEndpointSlice,
	})

	// Start the informers
	stopCh := ctx.Done()
	factory.Start(stopCh)

	// Wait for the informers to sync
	if !cache.WaitForCacheSync(stopCh,
		serviceInformer.HasSynced,
		endpointInformer.HasSynced,
	) {
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
		tr:      clientset.AuthenticationV1().TokenReviews(),
		caCert:  caCert,
		caKey:   caKey,
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

	tr clientAuthenticationv1.TokenReviewInterface

	caCert *x509.Certificate
	caKey  *ed25519.PrivateKey
}

func (s *serviceMeshServer) GetServices(ctx context.Context, req *smv1pb.GetServicesRequest) (*smv1pb.GetServicesResponse, error) {
	services := s.watcher.getServices(req.Services)
	return &smv1pb.GetServicesResponse{
		Services: services,
	}, nil
}

func (s *serviceMeshServer) SignCertificate(ctx context.Context, req *smv1pb.SignCertificateRequest) (*smv1pb.SignCertificateResponse, error) {
	fmt.Printf("Received request to sign certificate for %s\n", req.Name)

	resp, err := s.tr.Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     req.Token,
			Audiences: []string{"diy-service-mesh"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	if !resp.Status.Authenticated {
		return nil, fmt.Errorf("token not authenticated")
	}

	// We can use the tokenReview information to add extra information to the certificate.
	csrBlock, _ := pem.Decode(req.Csr)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid csr")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Validate the CSR with the tokenReview information
	if csr.Subject.CommonName != req.Name || csr.Subject.CommonName != resp.Status.User.Username {
		return nil, fmt.Errorf("invalid csr")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	_ = cert

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &cert, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}

	return &smv1pb.SignCertificateResponse{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}),
		Ca:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw}),
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

func createCertificateAuthority(ctx context.Context, s clientCorev1.SecretInterface) (*x509.Certificate, *ed25519.PrivateKey, error) {
	secret, err := s.Get(ctx, "diy-service-mesh-ca", metav1.GetOptions{})
	if err == nil {
		certBlock, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
		if certBlock == nil || certBlock.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("invalid certificate")
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}

		keyBlock, _ := pem.Decode(secret.Data[corev1.TLSPrivateKeyKey])
		if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
			return nil, nil, fmt.Errorf("invalid private key")
		}

		priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}

		privKey, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("invalid private key type")
		}

		return cert, &privKey, nil
	}

	// Create a self-signed certificate authority
	public, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"diy-service-mesh"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, public, priv)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	if _, err := s.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "diy-service-mesh-ca",
			Namespace: os.Getenv("POD_NAMESPACE"),
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certBytes,
			}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privKeyBytes,
			}),
		},
	}, metav1.CreateOptions{}); err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, &priv, nil
}
