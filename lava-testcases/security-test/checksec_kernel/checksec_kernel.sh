#!/bin/bash

set -x

OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
KRES="kres.json"

# 安装checksec
pkginstall(){
  dnf install -y git go
  git clone https://github.com/slimm609/checksec.sh.git && cd checksec.sh
  go build -o checksec main.go
  chmod +x /usr/local/bin/checksec
}

# 内核加固验证
kernel_hardening_test(){
  checksec kernel -o json >> $KRES
}


kernel_risk_lava(){
  # 内核加固验证：全部通过输出kernel pass，否则输出 配置项名称 + fail + 风险等级
  JSON_FILE="${1}"
  OUTPUT_FILE="${2:-$RESULT_FILE}"

  [ ! -f "$JSON_FILE" ] && { echo "Usage: $0 <json_file> [output_file]"; exit 1; }

  python3 - "$JSON_FILE" "$OUTPUT_FILE" << 'PYEOF'
import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

output_file = sys.argv[2]
# 配置项: (安全值, 风险等级)
# 等级: 3=高危, 2=中危, 1=低危
CHECK_RULES = {
    # 高危
    'CONFIG_STACKPROTECTOR': ('Enabled', 3),
    'CONFIG_STACKPROTECTOR_STRONG': ('Enabled', 3),
    'CONFIG_STRICT_KERNEL_RWX': ('Enabled', 3),
    'CONFIG_STRICT_MODULE_RWX': ('Enabled', 3),
    'CONFIG_HARDENED_USERCOPY': ('Enabled', 3),
    'CONFIG_RANDOMIZE_BASE': ('Enabled', 3),
    'CONFIG_SLAB_FREELIST_RANDOM': ('Enabled', 3),
    'CONFIG_SYN_COOKIES': ('Enabled', 3),
    'CONFIG_SECCOMP': ('Enabled', 3),
    'CONFIG_SECCOMP_FILTER': ('Enabled', 3),
    'CONFIG_VMAP_STACK': ('Enabled', 3),
    'CONFIG_FORTIFY_SOURCE': ('Enabled', 3),
    'CONFIG_STRICT_DEVMEM': ('Enabled', 3),
    'CONFIG_IO_STRICT_DEVMEM': ('Enabled', 3),
#   'kernel.randomize_va_space': ('Enabled', 3), 移除该项检查需要实际值为3才正常
    'kernel.kptr_restrict': ('Enabled', 3),
    'kernel.yama.ptrace_scope': ('Enabled', 3),
    'kernel.kexec_load_disabled': ('Enabled', 3),
    'net.core.bpf_jit_harden': ('Enabled', 3),
    'vm.unprivileged_userfaultfd': ('Enabled', 3),

    # 中危
    'CONFIG_SECURITY': ('Enabled', 2),
    'CONFIG_SECURITY_SELINUX': ('Enabled', 2),
    'CONFIG_SECURITY_LOCKDOWN_LSM': ('Enabled', 2),
    'CONFIG_SECURITY_LOCKDOWN_LSM_EARLY': ('Enabled', 2),
    'CONFIG_SECURITY_YAMA': ('Enabled', 2),
    'CONFIG_LIST_HARDENED': ('Enabled', 2),
    'CONFIG_DEBUG_LIST': ('Enabled', 2),
    'SELinux': ('Enabled', 2),
    'CONFIG_DEBUG_WX': ('Enabled', 2),
    'CONFIG_DEBUG_SG': ('Enabled', 2),
    'CONFIG_DEBUG_NOTIFIERS': ('Enabled', 2),
    'CONFIG_DEBUG_VIRTUAL': ('Enabled', 2),
    'CONFIG_SCHED_STACK_END_CHECK': ('Enabled', 2),
    'CONFIG_SECURITY_LANDLOCK': ('Enabled', 2),
    'kernel.unprivileged_bpf_disabled': ('Enabled', 2),
    'kernel.dmesg_restrict': ('Enabled', 2),
    'fs.protected_symlinks': ('Enabled', 2),
    'fs.protected_hardlinks': ('Enabled', 2),
    'fs.protected_fifos': ('Enabled', 2),
    'fs.protected_regular': ('Enabled', 2),

    # 低危
    'CONFIG_LDISC_AUTOLOAD': ('Disabled', 1),
    'CONFIG_SECURITY_SELINUX_BOOTPARAM': ('Disabled', 1),
    'CONFIG_SECURITY_SELINUX_DEVELOP': ('Disabled', 1),
    'dev.tty.ldisc_autoload': ('Disabled', 1),
    'dev.tty.legacy_tiocsti': ('Disabled', 1),
    'kernel.perf_event_paranoid': ('Enabled', 1),
}

fail_items = []

for item in data:
    name = item['name']
    value = item['value']

    if name not in CHECK_RULES:
        continue

    expect, level = CHECK_RULES[name]

    passed = False
    if expect == 'Enabled' and value == 'Enabled':
        passed = True
    elif expect == 'Disabled' and value == 'Disabled':
        passed = True

    if value in ('Partial', 'Unknown'):
        passed = False
        if value == 'Unknown':
            level = 1

    if not passed:
        display = name
        if name == 'vm.unprivileged_userfaultfd':
            display = 'vm.unprivileged_userfaultfd (应禁用)'
        fail_items.append((display, value, expect, level))

with open(output_file, 'w') as out:
    if not fail_items:
        out.write('kernel pass\n')
    else:
        fail_items.sort(key=lambda x: -x[3])
        for name, value, expect, level in fail_items:
            out.write(f'{name} fail {level}\n')
PYEOF

  # 补充 ASLR 实际值检查
  ASLR_VALUE=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unknown")

  if [ "$ASLR_VALUE" != "2" ]; then
      ASLR_MSG="kernel.randomize_va_space_actual fail 3 (当前值: $ASLR_VALUE, 期望: 2)"
      echo "$ASLR_MSG" >> "$OUTPUT_FILE"
  fi

  echo "结果已保存: $OUTPUT_FILE"
  cat "$OUTPUT_FILE"
}

echo "安装checksec"
pkginstall

echo "内核加固验证"
kernel_hardening_test

echo "结果转为lava result格式数据"
kernel_risk_lava "$KRES"




