- **通过`sendARP`函数发送`ARP`广播查询实时监测目标`MAC`地址，若有变动立即输出警告。<br />为应对复杂环境并实现快速判断，推荐结合`Wireshark`进行`ARP`报文分析。**

**检测到冲突会提示信息**

### 使用方法一
- 直接双击`arping.exe`根据提示输入检测目标`IP`
- 然后按`Enter(回车)`键

### 使用方法二

- 将`arping.exe`放入`C:\Windows`目录
- 打开`CMD(终端)`输入`arping <检测目标IP>`
- 然后按`Enter(回车)`键
