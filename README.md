# naivereal-tui

Windows TUI 客户端，用于管理 naivereal 内核节点。

这是从 [naive-reality](https://github.com/lipeiying032/naive-reality) 拆出的独立 TUI 仓库，并适配了当前内核的 QUIC/BBR 修改点。

## 已适配的内核修改点

- 支持 `bbr_profile`：
  - `standard`
  - `aggressive`
  - `conservative`
- 支持 `socket_recv_optimization`（QUIC UDP 接收优化开关）
- share link 支持参数：
  - `bbr_profile=standard|aggressive|conservative`
  - `socket_recv_optimization=true|false`

## 构建

```bash
# Windows
go build -o naivereal-tui.exe .

# Linux/macOS（仅测试/编译）
go build ./...
```

## 使用

启动后：

- `a` 添加节点（粘贴 share link）
- `c` 连接
- `d` 断开
- `x` 复制当前节点 share link
- `Tab` 切换页面

### share link 示例

标准 naive+https：

```text
naive+https://user:pass@example.com:8443?bbr_profile=aggressive&socket_recv_optimization=true#node
```

REALITY：

```text
naivereal://user:pass@203.0.113.10:443?server_name=www.microsoft.com&public_key=...&short_id=abcd&bbr_profile=aggressive#node
```

## 测试

```bash
go test ./...
```
