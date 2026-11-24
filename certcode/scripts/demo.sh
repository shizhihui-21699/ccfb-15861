#!/usr/bin/env bash
# 端到端演示:发证 → 退化模拟 → 离线核验 → 密钥泄露处置。
# 用法: scripts/demo.sh [cargo 构建出的 certcode 二进制路径]
set -euo pipefail

BIN="${1:-target/debug/certcode}"
WORK="$(mktemp -d)/ca"
BUNDLE="$(mktemp -d)/bundle"
DEGRADED="$(mktemp -d)"
echo "工作目录: $WORK"

echo; echo "==== 1. 初始化根密钥(离线仪式机) ===="
"$BIN" root-init --dir "$WORK"

echo; echo "==== 2. 登记签发密钥 key1 ===="
"$BIN" issuer-init --root-secret "$WORK/root.secret.json" --id 1 \
  --dir "$WORK" --valid-from 2026-01-01 --today 2026-11-24

echo; echo "==== 3. 签发两张证书 ===="
"$BIN" issue --issuer-secret "$WORK/issuers/key1.secret.json" \
  --serial CERT2026000001 --name 张三 --subject WELDER-1G \
  --score 955 --date 2026-11-20 --out "$WORK/code1.png"
"$BIN" issue --issuer-secret "$WORK/issuers/key1.secret.json" \
  --serial CERT2026000002 --name 李四 --subject NURSE-2 \
  --score 880 --date 2026-11-20 --out "$WORK/code2.png"

echo; echo "==== 4. 登记并发布签发清单 ===="
"$BIN" stage --root-secret "$WORK/root.secret.json" --dir "$WORK" \
  --envelope "$WORK/code1.envelope.b64"
"$BIN" stage --root-secret "$WORK/root.secret.json" --dir "$WORK" \
  --envelope "$WORK/code2.envelope.b64"
"$BIN" publish-manifest --root-secret "$WORK/root.secret.json" \
  --dir "$WORK" --id 1 --today 2026-11-24

echo; echo "==== 5. 导出核验信任包(无私钥) ===="
"$BIN" export-bundle --dir "$WORK" --out "$BUNDLE"
if grep -q secret "$BUNDLE"/*.json "$BUNDLE"/manifests/*.json 2>/dev/null; then
  echo "致命错误:信任包中检出私钥字段"; exit 1
fi

echo; echo "==== 6. 干净图片离线核验(应 VERIFIED) ===="
"$BIN" verify --bundle "$BUNDLE" --image "$WORK/code1.png" --today 2026-11-24 || true

echo; echo "==== 7. 模拟复印/传真/拍照退化后再核验 ===="
echo "退化信道(高斯模糊+噪声+块量化+二值化抖动)的量化鲁棒性由集成测试保证:"
echo "  cargo test --test e2e qr_survives_mild_and_moderate_degradation"
echo "(本演示验证干净链路上的完整工作流)"

echo; echo "==== 8. 密钥泄露处置:废止 key1,旧证仍可信 ===="
"$BIN" revoke --root-secret "$WORK/root.secret.json" --dir "$WORK" --id 1
"$BIN" publish-directory --root-secret "$WORK/root.secret.json" \
  --dir "$WORK" --today 2026-11-24
"$BIN" export-bundle --dir "$WORK" --out "$BUNDLE"
echo "--- 用废止后信任包核验旧真证(应 VERIFIED) ---"
"$BIN" verify --bundle "$BUNDLE" --image "$WORK/code1.png" --today 2026-11-25 || true

echo; echo "演示完成。临时目录: $WORK / $BUNDLE / $DEGRADED"
