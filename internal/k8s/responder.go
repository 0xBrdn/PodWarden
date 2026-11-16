package k8s

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/0xBrdn/PodWarden/internal/config"
)

type IncidentReport struct {
	IncidentID    string            `json:"incident_id"`
	Timestamp     time.Time         `json:"timestamp"`
	Rule          string            `json:"rule"`
	Priority      string            `json:"priority"`
	Output        string            `json:"output"`
	Namespace     string            `json:"namespace"`
	PodName       string            `json:"pod_name"`
	PodIP         string            `json:"pod_ip,omitempty"`
	NodeName      string            `json:"node_name,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Images        []string          `json:"images,omitempty"`
	ContainerLogs string            `json:"container_logs,omitempty"`
	Action        string            `json:"action"`
	HMACSignature string            `json:"hmac_sha256"`
	DryRun        bool              `json:"dry_run"`
}

type Responder struct {
	clientset *kubernetes.Clientset
	cfg       *config.Config
	logger    *slog.Logger
}

func NewResponder(cfg *config.Config, logger *slog.Logger) (*Responder, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("unable to load in-cluster or kubeconfig: %w", err)
		}
		logger.Info("using kubeconfig fallback", "path", kubeconfig)
	} else {
		logger.Info("using in-cluster config")
	}

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset: %w", err)
	}

	return &Responder{clientset: clientset, cfg: cfg, logger: logger}, nil
}

func (r *Responder) HandleAlert(ctx context.Context, rule, priority, output, namespace, podName string) error {
	incidentID := fmt.Sprintf("pw-%s-%s", config.Now(), podName)

	report := &IncidentReport{
		IncidentID: incidentID,
		Timestamp:  time.Now().UTC(),
		Rule:       rule,
		Priority:   priority,
		Output:     output,
		Namespace:  namespace,
		PodName:    podName,
		DryRun:     r.cfg.DryRun,
		Action:     "pending",
	}

	if err := r.collectForensics(ctx, report); err != nil {
		r.logger.Warn("forensics collection partial failure", "error", err, "incident", incidentID)
	}

	if r.cfg.DryRun {
		report.Action = "dry-run"
		r.logger.Info("DRY_RUN=true – pod will NOT be deleted", "pod", podName, "ns", namespace)
	} else {
		if err := r.deletePod(ctx, namespace, podName); err != nil {
			report.Action = "delete-failed"
			r.logger.Error("failed to delete pod", "error", err, "pod", podName, "ns", namespace)
		} else {
			report.Action = "deleted"
			r.logger.Info("pod deleted (grace period 0)", "pod", podName, "ns", namespace)
		}
	}

	report.HMACSignature = r.sign(report)

	return r.persist(report)
}

func (r *Responder) collectForensics(ctx context.Context, report *IncidentReport) error {
	pod, err := r.clientset.CoreV1().Pods(report.Namespace).Get(ctx, report.PodName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get pod: %w", err)
	}

	report.PodIP = pod.Status.PodIP
	report.NodeName = pod.Spec.NodeName
	report.Labels = pod.Labels

	images := make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	report.Images = images

	if len(pod.Spec.Containers) > 0 {
		containerName := pod.Spec.Containers[0].Name
		tailLines := int64(50)
		opts := &corev1.PodLogOptions{Container: containerName, TailLines: &tailLines}
		raw, err := r.clientset.CoreV1().Pods(report.Namespace).GetLogs(report.PodName, opts).Do(ctx).Raw()
		if err != nil {
			r.logger.Warn("unable to fetch container logs", "error", err, "container", containerName)
		} else {
			report.ContainerLogs = string(raw)
		}
	}
	return nil
}

func (r *Responder) deletePod(ctx context.Context, namespace, name string) error {
	grace := int64(0)
	return r.clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: &grace,
	})
}

func (r *Responder) sign(report *IncidentReport) string {
	payload := struct {
		IncidentID string    `json:"incident_id"`
		Timestamp  time.Time `json:"timestamp"`
		Rule       string    `json:"rule"`
		Priority   string    `json:"priority"`
		Namespace  string    `json:"namespace"`
		PodName    string    `json:"pod_name"`
		Action     string    `json:"action"`
	}{
		IncidentID: report.IncidentID,
		Timestamp:  report.Timestamp,
		Rule:       report.Rule,
		Priority:   report.Priority,
		Namespace:  report.Namespace,
		PodName:    report.PodName,
		Action:     report.Action,
	}
	b, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(r.cfg.HMACSigningKey))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

func (r *Responder) persist(report *IncidentReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Primary channel: structured JSON on stdout
	fmt.Println(string(data))

	// Best-effort disk write (non-fatal under read-only rootfs)
	if err := os.MkdirAll(r.cfg.IncidentDir, 0o750); err != nil {
		r.logger.Warn("cannot create incident directory", "dir", r.cfg.IncidentDir, "error", err)
		return nil
	}
	filename := filepath.Join(r.cfg.IncidentDir, report.IncidentID+".json")
	if err := os.WriteFile(filename, data, 0o640); err != nil {
		r.logger.Warn("cannot write incident file", "file", filename, "error", err)
		return nil
	}
	r.logger.Info("incident report persisted", "file", filename, "signature", report.HMACSignature[:16]+"...")
	return nil
}
