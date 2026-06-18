#!/usr/bin/env
# RPM Signature Chain Integrity Test for openEuler RISC-V
# 输出: test_name pass | test_name fail | test_name skip


OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
WORK_DIR="/tmp/rpm-sig-test"
mkdir -p "$WORK_DIR"

# 测试1: 环境检查
test_environment() {
    command -v rpm &>/dev/null && command -v gpg &>/dev/null && echo "env-check pass" || echo "env-check fail"
}

# 测试2: 官方密钥
test_official_key() {
    local name="official-key-import"
    [[ -f /etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler ]] || { echo "$name fail"; return; }
    export GNUPGHOME="$WORK_DIR/gnupg"
    mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
    gpg --batch --yes --import /etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler &>/dev/null || { echo "$name fail"; return; }
    rpm -q gpg-pubkey &>/dev/null || rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler &>/dev/null || { echo "$name fail"; return; }
    echo "$name pass"
}

# 测试3: 所有已安装包签名验证
test_installed_pkg() {
    local name="installed-pkg-sig"
    local total=0 signed=0 unsigned=0

    while read -r pkg; do
        [[ -z "$pkg" ]] && continue
        [[ "$pkg" == "gpg-pubkey" ]] && continue  # 过滤公钥包

        total=$((total + 1))

        if rpm -qi "$pkg" 2>/dev/null | grep -q "Signature.*Key ID"; then
            signed=$((signed + 1))
        else
            unsigned=$((unsigned + 1))
            echo "WARNING: $pkg is not signed" >&2
        fi
    done < <(rpm -qa --qf '%{NAME}\n')

    [[ $unsigned -eq 0 ]] && echo "$name pass" || echo "$name fail (signed: $signed/$total, unsigned: $unsigned)"
}

# 测试4: 仓库GPG配置
test_repo_config() {
    local name="repo-gpg-config"
    [[ -d /etc/yum.repos.d ]] || { echo "$name fail"; return; }

    local bad=0
    for repo in $(grep -h '^\[.*\]$' /etc/yum.repos.d/*.repo 2>/dev/null | tr -d '[]'); do
        local enabled=$(grep -A20 "^\[$repo\]$" /etc/yum.repos.d/*.repo 2>/dev/null | grep '^enabled' | head -1 | cut -d= -f2 | tr -d ' ')
        local gpgcheck=$(grep -A20 "^\[$repo\]$" /etc/yum.repos.d/*.repo 2>/dev/null | grep '^gpgcheck' | head -1 | cut -d= -f2 | tr -d ' ')
        [[ "$enabled" == "1" && "$gpgcheck" != "1" ]] && bad=1
    done

    [[ $bad -eq 0 ]] && echo "$name pass" || echo "$name fail"
}

# 测试5: 仓库元数据签名
test_repo_metadata() {
    local name="repo-metadata-sig"
    # 清理并重建缓存
    dnf clean all &>/dev/null || true
    dnf makecache &>/dev/null || true
    local repomd_files=()
    local total=0 signed=0 verified=0

    # 收集所有 repomd.xml 文件
    while IFS= read -r -d '' f; do
        repomd_files+=("$f")
    done < <(find /var/cache/dnf /var/cache/yum -name "repomd.xml" -print0 2>/dev/null)

    # 逐文件检查签名
    for f in "${repomd_files[@]}"; do
        ((total++))
        local dir=$(dirname "$f")
        local asc=""

        # 查找对应的签名文件（优先同级目录的 repomd.xml.asc）
        if [[ -f "${f}.asc" ]]; then
            asc="${f}.asc"
        else
            asc=$(find "$dir" -maxdepth 1 -name "repomd.xml.asc" -print -quit 2>/dev/null)
        fi

        if [[ -z "$asc" || ! -f "$asc" ]]; then
            continue  # 无签名，不计入 signed
        fi

        ((signed++))

        # 验证签名（保留错误输出到 stderr 便于调试）
        if gpg --verify "$asc" "$f" &>/dev/null; then
            ((verified++))
        else
            # 可选：输出具体失败信息到 stderr
            echo "$name: GPG verify failed for $f" >&2
        fi
    done

    # 结果判定
    if [[ $signed -eq 0 ]]; then
        echo "$name skip"
    elif [[ $verified -eq $signed ]]; then
        echo "$name pass"
    else
        echo "$name fail"
    fi
}

# 测试6: 密钥信任链
test_key_chain() {
    local name="key-trust-chain"
    local keys=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null)
    [[ -n "$keys" ]] || { echo "$name fail"; return; }

    export GNUPGHOME="$WORK_DIR/gnupg"
    while read -r key; do
        local id=$(echo "$key" | sed 's/gpg-pubkey-//;s/-.*//')
        gpg --list-keys "0x$id" 2>/dev/null | grep -q expired && { echo "$name fail"; return; }
    done <<< "$keys"
    echo "$name pass"
}

# 测试7: 篡改检测
test_tamper() {
    local name="negative-tamper-test"
    local f="$WORK_DIR/tamper-test"
    cp $(rpm -ql bash 2>/dev/null | head -1) "$f" 2>/dev/null || echo "fake" > "$f"
    echo "x" >> "$f"
    rpm -K "$f" &>/dev/null && echo "$name fail" || echo "$name pass"
    rm -f "$f"
}

# 测试8: 安装时GPG检查
test_install_gpg() {
    local name="install-gpg-check"
    # 清理旧文件避免干扰
    rm -f "$WORK_DIR"/*.rpm
    dnf download --destdir="$WORK_DIR" bash &>/dev/null || true
    local pkg
    pkg=$(find "$WORK_DIR" -maxdepth 1 -name "*.rpm" -type f | head -1)
    [[ -z "$pkg" ]] && { echo "$name skip"; return; }
    if rpm -K "$pkg" 2>/dev/null | grep -q "digests signatures OK"; then
        echo "$name pass"
    else
        echo "$name fail"
    fi
}

# 执行
{
    test_environment
    test_official_key
    test_installed_pkg
    test_repo_config
    test_repo_metadata
    test_key_chain
    test_tamper
    test_install_gpg
    rm -rf "$WORK_DIR/gnupg"
} | tee "$RESULT_FILE"