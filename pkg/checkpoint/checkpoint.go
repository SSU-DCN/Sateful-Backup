package checkpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"bytes"
	"io/ioutil"
	"net/http"

	pkgbackup "github.com/vmware-tanzu/velero/pkg/backup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PodInfo struct {
	Namespace string
	PodName   string
	Container string
	HostIP    string
}

func GetPodListByLabelSelector(c client.Client, request *pkgbackup.Request) (*corev1.PodList, error) {
	var selectorKey string
	var selectorValue string

	selector := request.Spec.LabelSelector.MatchLabels
	for key, value := range selector {
		selectorKey = key
		selectorValue = value
	}

	labelSelector := labels.SelectorFromSet(labels.Set{selectorKey: selectorValue})

	/*
		listOptions := metav1.ListOptions{
			LabelSelector: labelSelector,
		}
		podList, _ := clientset.CoreV1().Pods("").List(listOptions)
	*/

	podList := &corev1.PodList{}

	err := c.List(context.TODO(), podList, &client.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, err
	}

	return podList, nil
}

func GetPodInfoList(podList *corev1.PodList) ([]PodInfo, error) {
	podInfoList := make([]PodInfo, 0, len(podList.Items))

	for _, pod := range podList.Items {
		podInfo := PodInfo{
			Namespace: pod.Namespace,
			PodName:   pod.Name,
			Container: pod.Spec.Containers[0].Name, // 첫 번째 컨테이너의 이름을 가져옴
			HostIP:    pod.Status.HostIP,
		}
		podInfoList = append(podInfoList, podInfo)
	}

	return podInfoList, nil
}

func CallKubeletAPI(apiURL string, keyPath string, cacertPath string, certPath string) (string, error) {
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return "", err
	}

	caCert, err := ioutil.ReadFile(cacertPath)
	if err != nil {
		return "", err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		RootCAs:      caCertPool,
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}

	response, err := client.Post(apiURL, "application/json", bytes.NewBuffer([]byte{}))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

/*
func CallKubeletAPI(podInfo PodInfo) error {
	// API 엔드포인트 생성
	apiURL := fmt.Sprintf("https://%s:10250/checkpoint/%s/%s/%s \\\n --key /etc/kubernetes/pki/apiserver-kubelet-client.key \\\n --cacert /etc/kubernetes/pki/ca.crt \\\n --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt", podInfo.HostIP, podInfo.Namespace, podInfo.PodName, podInfo.Container)

	// HTTP 클라이언트 생성
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// API 호출
	resp, err := httpClient.Post(apiURL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 응답 본문 읽기
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 응답 출력
	fmt.Printf("API Response for Pod: %s\n%s\n", podInfo.PodName, string(body))

	return nil
}
*/
