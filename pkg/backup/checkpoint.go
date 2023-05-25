package backup

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"

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

func GetPodListByLabelSelector(c client.Client, request *Request) (*corev1.PodList, error) {

	//clientset 생성 하는 부분
	// podList := &corev1.PodList{}
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

func callKubeletAPI(podInfo PodInfo) error {
	// API 엔드포인트 생성
	apiURL := fmt.Sprintf("https://%s:10250/checkpoint/%s/%s/%s", podInfo.HostIP, podInfo.Namespace, podInfo.PodName, podInfo.Container)

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
