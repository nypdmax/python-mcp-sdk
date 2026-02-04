# 多协议认证集成测试说明

本文档说明如何运行多协议认证的集成测试，包括不同的协议发现方式和正向/负向测试。

## 测试脚本

### 1. `run_integration_test.sh` - 全面集成测试

这是最全面的测试脚本，测试所有协议发现方式和正向/负向场景。

**功能：**
- 测试 PRM 中的协议发现（优先级1）
- 测试路径相对统一发现（优先级2）
- 测试根路径统一发现（优先级3）
- 测试 OAuth fallback（优先级4）
- 正向测试：API Key 认证成功、工具调用成功
- 负向测试：无效 API Key、协议不匹配

**运行方式：**
```bash
cd python-mcp-sdk
./examples/clients/simple-auth-multiprotocol-client/run_integration_test.sh
```

**环境变量：**
- `MCP_RS_PORT`: Resource Server 端口（默认 8002）
- `MCP_AS_PORT`: Authorization Server 端口（默认 9000）
- `LOG_LEVEL`: 客户端日志级别（默认 WARNING）；设为 `DEBUG` 可查看鉴权发现日志（英文，`[Auth discovery]` 前缀）
- `RUN_OAUTH_FALLBACK=1`: 执行测试 4（OAuth fallback，需浏览器授权）

### 2. `run_multiprotocol_test.sh` - 单协议测试

测试单个协议的认证流程。

**运行方式：**
```bash
cd python-mcp-sdk
MCP_AUTH_PROTOCOL=api_key ./examples/clients/simple-auth-multiprotocol-client/run_multiprotocol_test.sh
```

**支持的协议：**
- `api_key`: API Key 认证（默认）
- `oauth`: OAuth 2.0 授权码流程
- `oauth_dpop`: OAuth 2.0 + DPoP
- `mutual_tls`: Mutual TLS（占位符，未实现）

**环境变量：**
- `MCP_AUTH_PROTOCOL`: 要测试的协议（默认 `api_key`）
- `MCP_SKIP_OAUTH`: 设置为 `1` 时跳过需要手动 OAuth 授权的测试
- `MCP_RS_PORT`: Resource Server 端口（默认 8002）
- `MCP_AS_PORT`: Authorization Server 端口（默认 9000）

## 协议发现优先级

客户端按照以下优先级顺序尝试协议发现：

1. **优先级1: PRM 中的协议信息**
   - 端点: `/.well-known/oauth-protected-resource/mcp`
   - 如果 PRM 包含 `mcp_auth_protocols` 字段，直接使用其中的协议列表

2. **优先级2: 路径相对统一发现（Way B）**
   - 端点: `/.well-known/authorization_servers/mcp`
   - 将资源路径（`/mcp`）附加到 `/.well-known/authorization_servers` 后面

3. **优先级3: 根路径统一发现**
   - 端点: `/.well-known/authorization_servers`
   - 在服务器根路径的统一发现端点

4. **优先级4: OAuth Fallback**
   - 如果统一发现失败，但 PRM 包含 `authorization_servers`，尝试 OAuth 协议发现

## 测试场景

### 正向测试

1. **PRM 协议发现**
   - 验证 PRM 端点返回 `mcp_auth_protocols`
   - 验证客户端能够使用 PRM 中的协议列表成功连接

2. **路径相对统一发现**
   - 验证 `/.well-known/authorization_servers/mcp` 端点可用
   - 验证端点返回协议列表

3. **根路径统一发现**
   - 验证 `/.well-known/authorization_servers` 端点可用
   - 验证端点返回协议列表

4. **API Key 认证成功**
   - 使用有效的 API Key 连接服务器
   - 成功调用工具（如 `get_time`）

### 负向测试

1. **无效 API Key**
   - 使用无效的 API Key 尝试连接
   - 验证返回认证失败错误（401）

2. **协议不匹配**
   - 尝试使用未实现的协议（如 `mutual_tls`）
   - 验证正确报告协议未实现

3. **发现端点不可用**
   - 验证当发现端点不可用时，客户端能够正确处理错误

## 示例输出

### 成功运行示例

```
=== 多协议认证集成测试 ===

启动测试环境...
✓ Authorization Server 已启动: http://localhost:9000/.well-known/oauth-authorization-server
✓ Multi-protocol RS (PRM) 已启动: http://localhost:8002/.well-known/oauth-protected-resource/mcp

=== 端点信息 ===
PRM端点: http://localhost:8002/.well-known/oauth-protected-resource/mcp
路径相对统一发现: http://localhost:8002/.well-known/authorization_servers/mcp
根路径统一发现: http://localhost:8002/.well-known/authorization_servers

=== 测试1: PRM中的协议发现（优先级1）===
✓ PRM端点: http://localhost:8002/.well-known/oauth-protected-resource/mcp (状态码: 200)
[PASS] PRM包含mcp_auth_protocols字段
[PASS] PRM包含预期的协议（oauth2, api_key）
[PASS] 客户端成功使用PRM协议发现并连接

=== 测试2: 路径相对统一发现（优先级2）===
✓ 路径相对统一发现端点: http://localhost:8002/.well-known/authorization_servers/mcp (状态码: 200)
[PASS] 路径相对统一发现端点返回协议列表

=== 测试3: 根路径统一发现（优先级3）===
✓ 根路径统一发现端点: http://localhost:8002/.well-known/authorization_servers (状态码: 200)
[PASS] 根路径统一发现端点返回协议列表

=== 测试5: API Key认证 - 正向测试 ===
[PASS] API Key认证成功，工具调用成功

=== 测试6: 无效API Key - 负向测试 ===
[PASS] 无效API Key正确返回认证失败

=== 测试7: 协议不匹配 - 负向测试 ===
[PASS] mutual_tls协议正确报告未实现

=== 测试结果汇总 ===
通过: 7
失败: 0
跳过: 1

所有测试通过！
```

## 故障排查

### 服务器启动失败

- 检查端口是否被占用：`lsof -i :8002` 或 `lsof -i :9000`
- 检查日志：`/tmp/mcp-as.log` 和 `/tmp/mcp-rs.log`

### 客户端连接失败

- 确认服务器已启动并监听正确端口
- 检查 API Key 是否正确（默认：`demo-api-key-12345`）
- 验证发现端点是否可访问：`curl http://localhost:8002/.well-known/authorization_servers`

### OAuth 测试失败

- 确保 Authorization Server 已启动
- 检查浏览器是否正确打开授权页面
- 验证回调 URL 是否正确（默认：`http://localhost:3031/callback`）

## 相关文档

- [simple-auth-multiprotocol 服务器 README](../../servers/simple-auth-multiprotocol/README.md)
- [多协议认证客户端 README](./README.md)
