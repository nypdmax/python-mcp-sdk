#!/usr/bin/env bash
# 全面的多协议认证集成测试脚本
# 测试不同的协议发现方式：PRM、路径相对统一发现、根路径统一发现、OAuth fallback
# 包含正向和负向测试
#
# 可选环境变量：
#   RUN_OAUTH_FALLBACK=1  执行测试4（OAuth fallback），需在浏览器中完成授权
#   LOG_LEVEL=DEBUG       Client log level (DEBUG shows auth discovery logs; script defaults to INFO)

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SIMPLE_AUTH_SERVER="${REPO_ROOT}/examples/servers/simple-auth"
MULTIPROTOCOL_SERVER="${REPO_ROOT}/examples/servers/simple-auth-multiprotocol"
MULTIPROTOCOL_CLIENT="${REPO_ROOT}/examples/clients/simple-auth-multiprotocol-client"
RS_PORT="${MCP_RS_PORT:-8002}"
AS_PORT="${MCP_AS_PORT:-9000}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cd "$REPO_ROOT"
echo -e "${BLUE}=== 多协议认证集成测试 ===${NC}\n"

uv sync --quiet 2>/dev/null || true

# macOS兼容的timeout函数（macOS默认没有timeout命令）
timeout_cmd() {
  local duration=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    # Linux系统有timeout命令
    timeout "$duration" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    # macOS通过brew安装的coreutils提供gtimeout
    gtimeout "$duration" "$@"
  else
    # 使用perl实现超时（macOS默认有perl）
    perl -e '
      my $timeout = shift;
      my $pid = fork();
      if ($pid == 0) {
        exec @ARGV;
      } else {
        eval {
          local $SIG{ALRM} = sub { kill 9, $pid; exit 124; };
          alarm $timeout;
          waitpid($pid, 0);
          alarm 0;
        };
        exit $? >> 8;
      }
    ' "$duration" "$@"
  fi
}

# 测试结果统计
PASSED=0
FAILED=0
SKIPPED=0

# 辅助函数
wait_for_url() {
  local url="$1"
  local name="$2"
  local max=30
  local n=0
  while ! curl -sSf -o /dev/null "$url" 2>/dev/null; do
    n=$((n + 1))
    if [ "$n" -ge "$max" ]; then
      echo -e "${RED}超时等待 $name at $url${NC}"
      return 1
    fi
    sleep 0.5
  done
  echo -e "${GREEN}✓ $name 已启动: $url${NC}"
}

check_endpoint() {
  local url="$1"
  local expected_status="${2:-200}"
  local description="$3"
  
  local status=$(curl -sS -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
  if [ "$status" = "$expected_status" ]; then
    echo -e "${GREEN}✓ $description: $url (状态码: $status)${NC}"
    return 0
  else
    echo -e "${RED}✗ $description: $url (期望状态码: $expected_status, 实际: $status)${NC}"
    return 1
  fi
}

test_passed() {
  PASSED=$((PASSED + 1))
  echo -e "${GREEN}[PASS] $1${NC}"
}

test_failed() {
  FAILED=$((FAILED + 1))
  echo -e "${RED}[FAIL] $1${NC}"
}

test_skipped() {
  SKIPPED=$((SKIPPED + 1))
  echo -e "${YELLOW}[SKIP] $1${NC}"
}

cleanup() {
  echo -e "\n${YELLOW}清理中...${NC}"
  [ -n "$AS_PID" ] && kill "$AS_PID" 2>/dev/null || true
  [ -n "$RS_PID" ] && kill "$RS_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  pkill -f "mcp-simple-auth-as" 2>/dev/null || true
  pkill -f "mcp-simple-auth-multiprotocol-rs" 2>/dev/null || true
}
trap cleanup EXIT

# 启动 Authorization Server
start_auth_server() {
  echo -e "\n${BLUE}启动 Authorization Server...${NC}"
  cd "$SIMPLE_AUTH_SERVER"
  uv run mcp-simple-auth-as --port="$AS_PORT" > /tmp/mcp-as.log 2>&1 &
  AS_PID=$!
  cd "$REPO_ROOT"
  wait_for_url "http://localhost:${AS_PORT}/.well-known/oauth-authorization-server" "Authorization Server"
}

# 启动 Resource Server
start_resource_server() {
  local api_keys="${1:-demo-api-key-12345}"
  local dpop_enabled="${2:-false}"
  
  echo -e "\n${BLUE}启动 Multi-protocol Resource Server...${NC}"
  cd "$MULTIPROTOCOL_SERVER"
  if [ "$dpop_enabled" = "true" ]; then
    uv run mcp-simple-auth-multiprotocol-rs --port="$RS_PORT" --auth-server="http://localhost:${AS_PORT}" --api-keys="$api_keys" --dpop-enabled > /tmp/mcp-rs.log 2>&1 &
  else
    uv run mcp-simple-auth-multiprotocol-rs --port="$RS_PORT" --auth-server="http://localhost:${AS_PORT}" --api-keys="$api_keys" > /tmp/mcp-rs.log 2>&1 &
  fi
  RS_PID=$!
  cd "$REPO_ROOT"
  wait_for_url "http://localhost:${RS_PORT}/.well-known/oauth-protected-resource/mcp" "Multi-protocol RS (PRM)"
}

# 测试1: PRM中的协议发现（优先级1）
test_prm_protocol_discovery() {
  echo -e "\n${BLUE}=== 测试1: PRM中的协议发现（优先级1）===${NC}"
  
  # 检查PRM端点
  if check_endpoint "http://localhost:${RS_PORT}/.well-known/oauth-protected-resource/mcp" 200 "PRM端点"; then
    local prm=$(curl -sS "http://localhost:${RS_PORT}/.well-known/oauth-protected-resource/mcp")
    if echo "$prm" | grep -q "mcp_auth_protocols"; then
      test_passed "PRM包含mcp_auth_protocols字段"
    else
      test_failed "PRM不包含mcp_auth_protocols字段"
      return 1
    fi
    
    # 验证协议列表
    if echo "$prm" | grep -q "oauth2" && echo "$prm" | grep -q "api_key"; then
      test_passed "PRM包含预期的协议（oauth2, api_key）"
    else
      test_failed "PRM不包含预期的协议"
      return 1
    fi
  else
    test_failed "PRM端点不可访问"
    return 1
  fi
  
  # 测试客户端使用PRM协议发现
  echo -e "${YELLOW}测试客户端使用PRM协议发现...${NC}"
  cd "$MULTIPROTOCOL_CLIENT"
  set +e
  OUT=$(printf "list\nquit\n" | timeout_cmd 10 env LOG_LEVEL="${LOG_LEVEL:-INFO}" MCP_SERVER_URL="http://localhost:${RS_PORT}/mcp" MCP_API_KEY="demo-api-key-12345" MCP_AUTH_PROTOCOL="api_key" uv run mcp-simple-auth-multiprotocol-client 2>&1)
  CODE=$?
  set -e
  
  if [ "$CODE" -eq 0 ] && echo "$OUT" | grep -q "Session initialized"; then
    test_passed "客户端成功使用PRM协议发现并连接"
  else
    test_failed "客户端使用PRM协议发现失败"
    echo "$OUT" | tail -20
    return 1
  fi
}

# 测试2: 路径相对统一发现（优先级2）
test_path_relative_discovery() {
  echo -e "\n${BLUE}=== 测试2: 路径相对统一发现（优先级2）===${NC}"
  
  # 检查路径相对统一发现端点
  if check_endpoint "http://localhost:${RS_PORT}/.well-known/authorization_servers/mcp" 200 "路径相对统一发现端点"; then
    local discovery=$(curl -sS "http://localhost:${RS_PORT}/.well-known/authorization_servers/mcp")
    if echo "$discovery" | grep -q "protocols"; then
      test_passed "路径相对统一发现端点返回协议列表"
    else
      test_failed "路径相对统一发现端点不返回协议列表"
      return 1
    fi
  else
    test_skipped "路径相对统一发现端点不可访问（可能服务器未配置）"
    return 0
  fi
}

# 测试3: 根路径统一发现（优先级3）
test_root_based_discovery() {
  echo -e "\n${BLUE}=== 测试3: 根路径统一发现（优先级3）===${NC}"
  
  # 检查根路径统一发现端点
  if check_endpoint "http://localhost:${RS_PORT}/.well-known/authorization_servers" 200 "根路径统一发现端点"; then
    local discovery=$(curl -sS "http://localhost:${RS_PORT}/.well-known/authorization_servers")
    if echo "$discovery" | grep -q "protocols"; then
      test_passed "根路径统一发现端点返回协议列表"
    else
      test_failed "根路径统一发现端点不返回协议列表"
      return 1
    fi
  else
    test_failed "根路径统一发现端点不可访问"
    return 1
  fi
}

# 测试4: OAuth fallback（优先级4）- 正向测试
# 默认跳过（需浏览器授权）。设置 RUN_OAUTH_FALLBACK=1 可执行此测试，例如：
#   RUN_OAUTH_FALLBACK=1 ./run_integration_test.sh
test_oauth_fallback_positive() {
  echo -e "\n${BLUE}=== 测试4: OAuth fallback（优先级4）- 正向测试 ===${NC}"
  
  if [ -z "${RUN_OAUTH_FALLBACK:-}" ]; then
    test_skipped "OAuth fallback需要手动浏览器授权，跳过自动化测试（设置 RUN_OAUTH_FALLBACK=1 可执行）"
    return 0
  fi

  echo -e "${YELLOW}将启动 OAuth 客户端，请在浏览器中完成授权（约 120 秒内）${NC}"
  cd "$MULTIPROTOCOL_CLIENT"
  set +e
  OUT=$(printf "list\ncall get_time {}\nquit\n" | timeout_cmd 120 env LOG_LEVEL="${LOG_LEVEL:-INFO}" MCP_SERVER_URL="http://localhost:${RS_PORT}/mcp" MCP_AUTH_PROTOCOL="oauth" uv run mcp-simple-auth-multiprotocol-client 2>&1)
  CODE=$?
  set -e
  cd "$REPO_ROOT"

  if [ "$CODE" -eq 0 ] && echo "$OUT" | grep -q "Session initialized" && echo "$OUT" | grep -q "get_time"; then
    test_passed "OAuth fallback 认证成功，工具调用成功"
  else
    test_failed "OAuth fallback 认证或工具调用失败（请确认已在浏览器完成授权）"
    echo "$OUT" | tail -30
    return 1
  fi
}

# 测试5: API Key认证 - 正向测试
test_api_key_positive() {
  echo -e "\n${BLUE}=== 测试5: API Key认证 - 正向测试 ===${NC}"
  
  cd "$MULTIPROTOCOL_CLIENT"
  set +e
  OUT=$(printf "list\ncall get_time {}\nquit\n" | timeout_cmd 15 env LOG_LEVEL="${LOG_LEVEL:-INFO}" MCP_SERVER_URL="http://localhost:${RS_PORT}/mcp" MCP_API_KEY="demo-api-key-12345" MCP_AUTH_PROTOCOL="api_key" uv run mcp-simple-auth-multiprotocol-client 2>&1)
  CODE=$?
  set -e
  
  if [ "$CODE" -eq 0 ] && echo "$OUT" | grep -q "Session initialized" && echo "$OUT" | grep -q "get_time"; then
    test_passed "API Key认证成功，工具调用成功"
  else
    test_failed "API Key认证或工具调用失败"
    echo "$OUT" | tail -30
    return 1
  fi
}

# 测试6: 无效API Key - 负向测试
test_api_key_negative() {
  echo -e "\n${BLUE}=== 测试6: 无效API Key - 负向测试 ===${NC}"
  
  cd "$MULTIPROTOCOL_CLIENT"
  set +e
  OUT=$(printf "list\nquit\n" | timeout_cmd 10 env LOG_LEVEL="${LOG_LEVEL:-INFO}" MCP_SERVER_URL="http://localhost:${RS_PORT}/mcp" MCP_API_KEY="invalid-key" MCP_AUTH_PROTOCOL="api_key" uv run mcp-simple-auth-multiprotocol-client 2>&1)
  CODE=$?
  set -e
  
  if [ "$CODE" -ne 0 ] || echo "$OUT" | grep -qiE "(401|unauthorized|authentication.*fail|invalid.*token)"; then
    test_passed "无效API Key正确返回认证失败"
  else
    test_failed "无效API Key未正确返回认证失败"
    echo "$OUT" | tail -20
    return 1
  fi
}

# 测试7: 协议不匹配 - 负向测试
test_protocol_mismatch() {
  echo -e "\n${BLUE}=== 测试7: 协议不匹配 - 负向测试 ===${NC}"
  
  cd "$MULTIPROTOCOL_CLIENT"
  set +e
  OUT=$(printf "list\nquit\n" | timeout_cmd 10 env LOG_LEVEL="${LOG_LEVEL:-INFO}" MCP_SERVER_URL="http://localhost:${RS_PORT}/mcp" MCP_AUTH_PROTOCOL="mutual_tls" uv run mcp-simple-auth-multiprotocol-client 2>&1)
  CODE=$?
  set -e
  
  if echo "$OUT" | grep -qiE "(not.*implement|mutual.*tls.*not|placeholder)"; then
    test_passed "mutual_tls协议正确报告未实现"
  else
    test_failed "mutual_tls协议未正确报告未实现"
    echo "$OUT" | tail -20
    return 1
  fi
}

# 测试8: 发现端点优先级验证
test_discovery_priority() {
  echo -e "\n${BLUE}=== 测试8: 发现端点优先级验证 ===${NC}"
  
  # 验证PRM优先级最高
  local prm=$(curl -sS "http://localhost:${RS_PORT}/.well-known/oauth-protected-resource/mcp")
  if echo "$prm" | grep -q "mcp_auth_protocols"; then
    test_passed "PRM包含mcp_auth_protocols，优先级1生效"
  else
    test_failed "PRM不包含mcp_auth_protocols"
    return 1
  fi
  
  # 验证统一发现端点也可用（作为fallback）
  if check_endpoint "http://localhost:${RS_PORT}/.well-known/authorization_servers" 200 "统一发现端点（fallback）"; then
    test_passed "统一发现端点可用，可作为fallback"
  else
    test_failed "统一发现端点不可用"
    return 1
  fi
}

# 主测试流程
main() {
  echo -e "${BLUE}启动测试环境...${NC}"
  
  # 启动服务器
  start_auth_server
  start_resource_server "demo-api-key-12345" "false"
  
  sleep 2
  
  # 显示端点信息
  echo -e "\n${BLUE}=== 端点信息 ===${NC}"
  echo "PRM端点: http://localhost:${RS_PORT}/.well-known/oauth-protected-resource/mcp"
  echo "路径相对统一发现: http://localhost:${RS_PORT}/.well-known/authorization_servers/mcp"
  echo "根路径统一发现: http://localhost:${RS_PORT}/.well-known/authorization_servers"
  echo ""
  
  # 运行测试
  test_prm_protocol_discovery || true
  test_path_relative_discovery || true
  test_root_based_discovery || true
  test_oauth_fallback_positive || true
  test_api_key_positive || true
  test_api_key_negative || true
  test_protocol_mismatch || true
  test_discovery_priority || true
  
  # 输出测试结果
  echo -e "\n${BLUE}=== 测试结果汇总 ===${NC}"
  echo -e "${GREEN}通过: $PASSED${NC}"
  echo -e "${RED}失败: $FAILED${NC}"
  echo -e "${YELLOW}跳过: $SKIPPED${NC}"
  echo ""
  
  if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
  else
    echo -e "${RED}有 $FAILED 个测试失败${NC}"
    exit 1
  fi
}

main "$@"
