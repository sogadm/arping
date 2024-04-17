package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

const redColor = "\033[31m"

func colorizeRed(text string) string {
	return fmt.Sprintf("%s%s\033[0m", redColor, text)
}

var lastSeenMac = make(map[string]string)

func main() {
	fmt.Println("arping 版本: V1.0.5 由 https://osed.cn 提供")

	targetIP := ""
	if len(os.Args) > 1 {
		targetIP = os.Args[1]
	}

	for {
		if targetIP == "" {
			fmt.Print("请输入IP: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				targetIP = scanner.Text()
			}
			if targetIP == "" {
				fmt.Println("IP不能为空")
				continue
			}
		}

		// 创建一个通道用于通知goroutines立即退出
		exitSignalCh := make(chan struct{})

		// 创建一个新的goroutine来监听Ctrl+C
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			<-c
			close(exitSignalCh) // 关闭通道，通知所有goroutine立即退出
			signal.Stop(c)      // 停止监听信号，这样可以重新开始监听
		}()

		arpCheckLoop(targetIP, exitSignalCh)

		// 重置targetIP以允许输入新的IP地址
		targetIP = ""
	}
}

func arpCheckLoop(targetIP string, exitSignalCh chan struct{}) {
	for {
		select {
		case <-exitSignalCh:
			return
		default:
			performArpCheck(targetIP)
			time.Sleep(500 * time.Millisecond) // 每500毫秒执行一次ARP查询
		}
	}
}

func performArpCheck(targetIP string) {
	macAddr, err := sendARP(targetIP)
	if err != nil {
		// 不再输出详细的错误信息，仅简单提示没有MAC地址
		fmt.Printf("%s 没有响应\n", targetIP)
		return
	}

	fmt.Printf("IP %s - MAC %s\n", targetIP, macAddr)
	previousMac, exists := lastSeenMac[targetIP]
	if exists && macAddr != previousMac {
		fmt.Printf(colorizeRed("发现IP冲突!IP:%s\n原MAC: %s\n现MAC: %s\n"), targetIP, previousMac, macAddr)
	}
	lastSeenMac[targetIP] = macAddr // 更新历史MAC地址
}

func sendARP(destIP string) (string, error) {
	dst := net.ParseIP(destIP).To4()
	if dst == nil {
		return "", fmt.Errorf("无效的IP地址")
	}

	src := make([]byte, 4) // 本机IP地址，0.0.0.0表示任意
	mac := make([]byte, 6) // 目标MAC地址
	maclen := uint32(len(mac))

	dll := syscall.MustLoadDLL("iphlpapi.dll")
	proc := dll.MustFindProc("SendARP")

	ret, _, callErr := proc.Call(
		uintptr(binary.LittleEndian.Uint32(dst)),
		uintptr(binary.LittleEndian.Uint32(src)),
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&maclen)),
	)
	if ret != 0 {
		return "", fmt.Errorf("SendARP调用失败: %v", callErr)
	}

	return net.HardwareAddr(mac).String(), nil
}