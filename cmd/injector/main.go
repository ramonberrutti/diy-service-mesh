package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/sync/errgroup"

	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var certFile, keyFile = os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if certFile == "" || keyFile == "" {
		panic("CERT_FILE and KEY_FILE must be set")
	}

	// Mutate webhook.
	mux := http.NewServeMux()
	mux.HandleFunc("/inject", func(w http.ResponseWriter, r *http.Request) {
		var a admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if a.Request == nil {
			http.Error(w, "missing request", http.StatusBadRequest)
			return
		}

		a.Response = mutate(&a)
		a.Request = nil
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(a); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		<-ctx.Done()
		return server.Shutdown(context.Background())
	})

	g.Go(func() error {
		return server.ListenAndServeTLS(certFile, keyFile)
	})

	if err := g.Wait(); err != nil {
		if err != http.ErrServerClosed {
			panic(err)
		}
	}
}

func mutate(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	req := ar.Request
	if req.Operation != admissionv1.Create || req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		}
	}

	var pod v1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return &admissionv1.AdmissionResponse{
			UID: req.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	// Check if the pod contains the inject annotation.
	if v, ok := pod.Annotations["diy-service-mesh/inject"]; !ok || strings.ToLower(v) != "true" {
		return &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		}
	}

	// Add the initContainer to the pod.
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, v1.Container{
		Name:            "proxy-init",
		Image:           os.Getenv("IMAGE_TO_DEPLOY_PROXY_INIT"),
		ImagePullPolicy: v1.PullAlways,
		SecurityContext: &v1.SecurityContext{
			RunAsNonRoot: func(b bool) *bool { return &b }(false),
			RunAsUser:    func(i int64) *int64 { return &i }(0),
			Capabilities: &v1.Capabilities{
				Add:  []v1.Capability{"NET_ADMIN", "NET_RAW"},
				Drop: []v1.Capability{"ALL"},
			},
			ReadOnlyRootFilesystem: func(b bool) *bool { return &b }(true),
		},
	})

	// Add the sidecar container to the pod.
	pod.Spec.Containers = append(pod.Spec.Containers, v1.Container{
		Name:            "proxy",
		Image:           os.Getenv("IMAGE_TO_DEPLOY_PROXY"),
		ImagePullPolicy: v1.PullAlways,
		SecurityContext: &v1.SecurityContext{
			RunAsNonRoot:             func(b bool) *bool { return &b }(true),
			RunAsUser:                func(i int64) *int64 { return &i }(1337),
			RunAsGroup:               func(i int64) *int64 { return &i }(1337),
			ReadOnlyRootFilesystem:   func(b bool) *bool { return &b }(true),
			AllowPrivilegeEscalation: func(b bool) *bool { return &b }(false),
		},
		Env: []v1.EnvVar{
			{
				Name:  "SERVICE_MESH_TOKEN_FILE",
				Value: "/var/run/secrets/diy-service-mesh/token",
			},
		},
		VolumeMounts: []v1.VolumeMount{
			{
				Name:      "proxy-token",
				MountPath: "/var/run/secrets/diy-service-mesh",
				ReadOnly:  true,
			},
		},
	})

	pod.Spec.Volumes = append(pod.Spec.Volumes,
		v1.Volume{
			Name: "proxy-token",
			VolumeSource: v1.VolumeSource{
				Projected: &v1.ProjectedVolumeSource{
					Sources: []v1.VolumeProjection{
						{
							ServiceAccountToken: &v1.ServiceAccountTokenProjection{
								Audience:          "diy-service-mesh",
								ExpirationSeconds: func(i int64) *int64 { return &i }(3600),
								Path:              "token",
							},
						},
					},
				},
			},
		},
	)

	patch := []map[string]any{
		{
			"op":    "replace",
			"path":  "/spec/initContainers",
			"value": pod.Spec.InitContainers,
		},
		{
			"op":    "replace",
			"path":  "/spec/containers",
			"value": pod.Spec.Containers,
		},
		{
			"op":    "replace",
			"path":  "/spec/volumes",
			"value": pod.Spec.Volumes,
		},
	}

	podBytes, err := json.Marshal(patch)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			UID: req.UID,
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
		AuditAnnotations: map[string]string{
			"proxy-injected": "true",
		},
		Patch:     podBytes,
		PatchType: &patchType,
	}
}
