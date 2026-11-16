package k8s

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/0xBrdn/PodWarden/internal/config"
)

// Possible values of IncidentReport.Action.
const (
	ActionDeleted     = "deleted"
	ActionDryRun      = "dry-run"
	ActionDeleteFail  = "delete-failed"
	ActionAlreadyGone = "already-gone"
	ActionRateLimited = "skipped-rate-limited"
)

// SchemaVersion is bumped whenever the signed report layout changes.
const SchemaVersion = 2

// ErrDuplicate is returned when an alert for the same pod was already handled
// within the deduplication window.
var ErrDuplicate = errors.New("duplicate alert within deduplication window")

// IncidentReport is the structured forensic artifact produced for every
// actionable alert. The HMAC covers every field of the report except the
// signature itself.
type IncidentReport struct {
	SchemaVersion  int               `json:"schema_version"`
	IncidentID     string            `json:"incident_id"`
	Timestamp      time.Time         `json:"timestamp"`
	Rule           string            `json:"rule"`
	Priority       string            `json:"priority"`
	Output         string            `json:"output"`
	Namespace      string            `json:"namespace"`
	PodName        string            `json:"pod_name"`
	PodUID         string            `json:"pod_uid,omitempty"`
	PodIP          string            `json:"pod_ip,omitempty"`
	NodeName       string            `json:"node_name,omitempty"`
	ServiceAccount string            `json:"service_account,omitempty"`
	Owners         []string          `json:"owners,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Images         []string          `json:"images,omitempty"`
	ContainerLogs  map[string]string `json:"container_logs,omitempty"`
	Action         string            `json:"action"`
	ActionError    string            `json:"action_error,omitempty"`
	DryRun         bool              `json:"dry_run"`
	HMACSignature  string            `json:"hmac_sha256"`
}

// Responder encapsulates Kubernetes client interactions and incident handling.
type Responder struct {
	clientset kubernetes.Interface
	cfg       *config.Config
	logger    *slog.Logger
	guard     *guard
	out       io.Writer
}

// NewResponder builds a Kubernetes client (in-cluster first, then kubeconfig)
// and returns a ready-to-use Responder.
func NewResponder(cfg *config.Config, logger *slog.Logger) (*Responder, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		// Fallback for local development / Kind from the host.
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

	return NewResponderWithClientset(cfg, logger, clientset), nil
}

// NewResponderWithClientset is used by tests (and advanced callers) to inject
// a kubernetes.Interface (e.g. fake.NewSimpleClientset).
func NewResponderWithClientset(cfg *config.Config, logger *slog.Logger, cs kubernetes.Interface) *Responder {
	return &Responder{
		clientset: cs,
		cfg:       cfg,
		logger:    logger,
		guard:     newGuard(cfg.DedupWindow, cfg.MaxActionsPerMinute),
		out:       os.Stdout,
	}
}

// SetOutput redirects the one-line JSON incident stream (stdout by default).
func (r *Responder) SetOutput(w io.Writer) { r.out = w }

// Ready checks that the Kubernetes API is reachable with our credentials.
func (r *Responder) Ready(ctx context.Context) error {
	_, err := r.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{Limit: 1})
	return err
}

// HandleAlert performs the full active-response workflow for a validated alert:
// forensics first, then containment, then a signed report.
//
// It returns ErrDuplicate when the alert was already handled recently.
func (r *Responder) HandleAlert(ctx context.Context, rule, priority, output, namespace, podName string) (*IncidentReport, error) {
	key := namespace + "/" + podName
	if !r.guard.reserve(key) {
		return nil, ErrDuplicate
	}

	now := time.Now().UTC()
	report := &IncidentReport{
		SchemaVersion: SchemaVersion,
		IncidentID:    newIncidentID(now, podName),
		Timestamp:     now,
		Rule:          rule,
		Priority:      priority,
		Output:        output,
		Namespace:     namespace,
		PodName:       podName,
		DryRun:        r.cfg.DryRun,
	}

	// 1. Collect forensic metadata + logs BEFORE touching the pod.
	if err := r.collectForensics(ctx, report); err != nil {
		r.logger.Warn("forensics collection partial failure", "error", err, "incident", report.IncidentID)
		// Keep going: we still want to contain the pod even with incomplete evidence.
	}

	// 2. Decide and execute the containment action.
	switch {
	case r.cfg.DryRun:
		report.Action = ActionDryRun
		r.logger.Info("DRY_RUN=true - pod will NOT be deleted", "pod", podName, "ns", namespace)

	case !r.guard.allowAction():
		report.Action = ActionRateLimited
		r.logger.Error("circuit breaker open - deletion skipped, evidence kept",
			"pod", podName, "ns", namespace, "max_per_minute", r.cfg.MaxActionsPerMinute)

	default:
		err := r.deletePod(ctx, namespace, podName, report.PodUID)
		switch {
		case err == nil:
			report.Action = ActionDeleted
			r.logger.Info("pod deleted (grace period 0)", "pod", podName, "ns", namespace)
		case apierrors.IsNotFound(err):
			report.Action = ActionAlreadyGone
			r.logger.Info("pod already gone", "pod", podName, "ns", namespace)
		default:
			report.Action = ActionDeleteFail
			report.ActionError = err.Error()
			r.logger.Error("failed to delete pod", "error", err, "pod", podName, "ns", namespace)
		}
	}

	// 3. Sign the full report.
	report.HMACSignature = Sign(*report, r.cfg.HMACSigningKey)

	// 4. Persist + emit.
	if err := r.persist(report); err != nil {
		r.logger.Error("failed to persist incident report", "error", err, "incident", report.IncidentID)
		return report, err
	}
	return report, nil
}

func (r *Responder) collectForensics(ctx context.Context, report *IncidentReport) error {
	pod, err := r.clientset.CoreV1().Pods(report.Namespace).Get(ctx, report.PodName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get pod: %w", err)
	}

	report.PodUID = string(pod.UID)
	report.PodIP = pod.Status.PodIP
	report.NodeName = pod.Spec.NodeName
	report.ServiceAccount = pod.Spec.ServiceAccountName
	report.Labels = pod.Labels

	for _, o := range pod.OwnerReferences {
		report.Owners = append(report.Owners, o.Kind+"/"+o.Name)
	}

	report.Images = make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		report.Images = append(report.Images, c.Image)
	}

	tail := r.cfg.LogTailLines
	if tail <= 0 {
		tail = 50
	}
	limit := int64(64 << 10) // 64 KiB per container, keeps reports and stdout bounded

	logs := make(map[string]string, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		opts := &corev1.PodLogOptions{Container: c.Name, TailLines: &tail, LimitBytes: &limit}
		raw, err := r.clientset.CoreV1().Pods(report.Namespace).GetLogs(report.PodName, opts).Do(ctx).Raw()
		if err != nil {
			r.logger.Warn("unable to fetch container logs", "error", err, "container", c.Name)
			continue
		}
		logs[c.Name] = string(raw)
	}
	if len(logs) > 0 {
		report.ContainerLogs = logs
	}
	return nil
}

// deletePod kills the pod immediately. When the UID is known it is used as a
// precondition so that we never delete a *different* pod that reused the name
// (StatefulSets) between the alert and the deletion.
func (r *Responder) deletePod(ctx context.Context, namespace, name, uid string) error {
	grace := int64(0)
	opts := metav1.DeleteOptions{GracePeriodSeconds: &grace}
	if uid != "" {
		u := types.UID(uid)
		opts.Preconditions = &metav1.Preconditions{UID: &u}
	}
	return r.clientset.CoreV1().Pods(namespace).Delete(ctx, name, opts)
}

// Sign returns the hex HMAC-SHA256 of the whole report, signature field excluded.
func Sign(report IncidentReport, key string) string {
	report.HMACSignature = ""
	b, _ := json.Marshal(report) // struct marshalling is deterministic; cannot fail here
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyReport checks the HMAC of a serialized incident report in constant time.
// Only fields known to IncidentReport are covered by the signature.
func VerifyReport(data []byte, key string) (bool, error) {
	var rep IncidentReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return false, fmt.Errorf("invalid report JSON: %w", err)
	}
	got, err := hex.DecodeString(rep.HMACSignature)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}
	want, _ := hex.DecodeString(Sign(rep, key))
	return hmac.Equal(got, want), nil
}

func (r *Responder) persist(report *IncidentReport) error {
	// Primary channel: ONE compact JSON line on stdout (log shippers / SIEM friendly).
	line, err := json.Marshal(report)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.out, string(line))

	// Secondary channel: pretty file on disk. Best effort (emptyDir in the lab).
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(r.cfg.IncidentDir, 0o750); err != nil {
		r.logger.Warn("cannot create incident directory", "dir", r.cfg.IncidentDir, "error", err)
		return nil
	}
	filename := filepath.Join(r.cfg.IncidentDir, filepath.Base(report.IncidentID)+".json")
	if err := os.WriteFile(filename, data, 0o640); err != nil {
		r.logger.Warn("cannot write incident file", "file", filename, "error", err)
		return nil
	}
	r.logger.Info("incident report persisted", "file", filename, "signature", report.HMACSignature[:16]+"...")
	return nil
}

func newIncidentID(now time.Time, pod string) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	if len(pod) > 63 {
		pod = pod[:63]
	}
	return fmt.Sprintf("pw-%s-%s-%s", now.Format("20060102T150405Z"), hex.EncodeToString(b[:]), pod)
}
