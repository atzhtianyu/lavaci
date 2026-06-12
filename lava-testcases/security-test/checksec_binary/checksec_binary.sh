#!/bin/bash

set -x

OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
BRES="bres.json"  # 存放目录/bin的二进制加固结果
UBRES="ubres.json"   # 存放目录/usr/bin的二进制加固结果
SBRES="sbres.json"   # 存放目录/sbin的二进制加固结果
USBRES="usbres.json"   # 存放目录/usr/sbin的二进制加固结果
RESDIR=()
SCANDIR=()

# 安装checksec
pkginstall(){
  dnf install -y git go
  git clone https://github.com/slimm609/checksec.sh.git && cd checksec.sh
  go build -o checksec main.go
  cp checksec /usr/local/bin/checksec
  chmod +x /usr/local/bin/checksec
}

# 二进制加固验证
binary_hardening_test(){
  # 检查 /bin /sbin /usr/bin /usr/sbin
  if [ -L "/bin" ] && [ -L "/sbin" ]; then
    echo "[*] 检测到 UsrMerge: /bin -> $(readlink /bin), /sbin -> $(readlink /sbin)"
    echo "[*] 仅扫描真实路径: /usr/bin, /usr/sbin"
    RESDIR=($UBRES $USBRES)
    SCANDIR=(/usr/bin /usr/sbin)
  else
    echo "[*] 未检测到 UsrMerge，使用传统四目录布局"
    echo "[*] 扫描完整路径: /bin, /sbin, /usr/bin, /usr/sbin"
    RESDIR=($BRES $SBRES $UBRES $USBRES)
    SCANDIR=(/bin /sbin /usr/bin /usr/sbin)
  fi
  if [ "${#SCANDIR[@]}" -ne "${#RESDIR[@]}" ]; then
    echo "[!] 错误: SCANDIR(${#SCANDIR[@]}) 与 RESDIR(${#RESDIR[@]}) 数量不匹配！"
    exit 1
  fi
  for i in "${!SCANDIR[@]}"; do
    scan_path="${SCANDIR[$i]}"
    res_file="${RESDIR[$i]}"
    echo "[*] 正在扫描目录: $scan_path"
    echo "[*] 结果输出至: $res_file"
    checksec dir "$scan_path" -o json > "$res_file"
  done

}

# 处理验证结果为lava格式
binary_risk_lava(){
  JSON_FILE="${1}"
  DIRNAME="${2}"
  OUTPUT_FILE="${3:-$RESULT_FILE}"

  [ ! -f "$JSON_FILE" ] && { echo "Usage: $0 <json_file> <dirname> [output_file]"; exit 1; }

  python3 - "$JSON_FILE" "$DIRNAME" "$OUTPUT_FILE" << 'PYEOF'
import json
import sys
import re

with open(sys.argv[1]) as f:
    data = json.load(f)
dirname = sys.argv[2]
out = open(sys.argv[3], 'a')

# 0=INFO(通过), 1=LOW, 2=MEDIUM, 3=HIGH
HIGH_RISK = [
    # 特权程序
    r'su(d|do)$', r'passw(d|ord)$', r'login$', r'mount$', r'umount$',
    r'ping$', r'ping6$', r'pkexec$', r'chsh$', r'chfn$', r'newgrp$',
    r'gpasswd$', r'crontab$', r'at$', r'batch$', r'fusermount$',
    r'ntfs-3g$', r'mount\.nfs$', r'mount\.cifs$',
    # 系统服务/守护进程
    r'ssh(d|)$', r'Xorg$', r'Xwayland$', r'dbus-daemon$', r'dbus-broker$',
    r'polkitd$', r'rtkit-daemon$', r'accounts-daemon$', r'colord$',
    # systemd 核心组件
    r'systemd$', r'systemd-journald$', r'systemd-networkd$', r'systemd-resolved$',
    r'systemd-logind$', r'systemd-machined$', r'systemd-timesyncd$',
    # 网络服务
    r'NetworkManager$', r'firewalld$', r'auditd$', r'sssd$', r'httpd$',
    r'nginx$', r'named$', r'bind$', r'mysqld$', r'mariadbd$', r'postgres$',
    r'redis-server$', r'mongod$', r'memcached$', r'vsftpd$', r'proftpd$',
    r'smbd$', r'nmbd$', r'rpc\..*', r'telnetd$', r'inetd$', r'xinetd$',
    # 容器/虚拟化
    r'dockerd$', r'containerd$', r'containerd-shim$', r'crio$', r'podman$',
    r'kubelet$', r'kube-proxy$', r'kube-apiserver$', r'kube-controller-manager$',
    r'etcd$', r'flanneld$', r'calico-node$',
    # 其他高危
    r'svnserve$', r'git-daemon$', r'rsyncd$', r'lighttpd$', r'apache2$',
    r'php-fpm$', r'uwsgi$', r'gunicorn$', r'tomcat$', r'java$', r'jvm$',
]

DEV_TOOL = [
    # 编译器
    r'gcc$', r'g\+\+$', r'clang$', r'clang\+\+$', r'cc$', r'c\+\+$',
    r'icc$', r'tcc$', r'pcc$', r'rustc$', r'go$', r'gofmt$',
    r'javac$', r'kotlin$', r'scala$', r'groovyc$',
    # 链接器/归档器
    r'ld$', r'ld\.bfd$', r'ld\.gold$', r'ld\.lld$', r'ar$', r'nm$',
    r'ranlib$', r'strip$', r'objcopy$', r'objdump$', r'readelf$',
    r'strings$', r'size$', r'addr2line$', r'c++filt$',
    # 构建工具
    r'make$', r'cmake$', r'ninja$', r'meson$', r'autoconf$', r'automake$',
    r'libtool$', r'pkg-config$', r'configure$', r'premake$',
    # 调试/分析工具
    r'gdb$', r'lldb$', r'valgrind$', r'perf$', r'strace$', r'ltrace$',
    r'ptrace$', r'lto-dump$', r'gcov$', r'gcov-dump$', r'gcov-tool$',
    r'llvm-.*', r'llc$', r'opt$', r'lli$',
    # 预处理
    r'cpp$', r'm4$', r'flex$', r'bison$', r'yacc$',
    # 其他开发工具
    r'git$', r'svn$', r'hg$', r'cvs$', r'bzr$', r'fossil$',
    r'cargo$', r'npm$', r'yarn$', r'pnpm$', r'pip[0-9]*$', r'gem$',
    r'composer$', r'maven$', r'gradle$', r'ant$', r'sbt$',
    r'protoc$', r'thrift$', r'grpc_c_plugin$',
]

DOC_TOOL = [
    # Graphviz
    r'dot$', r'neato$', r'circo$', r'fdp$', r'sfdp$', r'twopi$',
    r'patchwork$', r'acyclic$', r'gvpr$', r'tred$', r'unflatten$',
    r'osage$', r'gml2gv$', r'gv2gml$', r'graphml2gv$', r'mm2gv$',
    # 字体/排版
    r'fc-list$', r'fc-pattern$', r'fc-query$', r'fc-scan$', r'fc-match$',
    r'fc-cache$', r'fc-cat$', r'fc-conflist$', r'fc-validate$',
    r'fc-format$', r'fc-match$', r'fc-query$',
    # GTK/GNOME 工具
    r'gsettings$', r'gio$', r'gio-querymodules', r'glib-compile-schemas$',
    r'gtk-update-icon-cache$', r'gtk-query-immodules', r'gdk-pixbuf-query-loaders',
    # 文档转换
    r'ghostscript$', r'gs$', r'pdftotext$', r'pdfinfo$', r'pdfimages$',
    r'dvipdf$', r'ps2pdf$', r'epstopdf$', r'enscript$',
    # 其他文档工具
    r'clear$', r'tabs$', r'tput$', r'reset$', r'mesg$', r'wall$',
    r'write$', r'banner$', r'figlet$', r'toilet$',
    # 图像处理
    r'convert$', r'identify$', r'mogrify$', r'montage$', r'composite$',
    r'compare$', r'stream$', r'animate$', r'display$', r'import$',
    # 其他
    r'source-highlight', r'highlight$', r'pygmentize$', r'bat$',
    r'less$', r'more$', r'most$', r'pg$', r'lv$',
]

INTERPRETER = [
    # Python
    r'python[0-9.]*$', r'python3$', r'python2$', r'pypy[0-9]*$', r'ipython$',
    r'pydoc[0-9]*$', r'pdb[0-9]*$', r'pyvenv', r'virtualenv$',
    # Perl
    r'perl[0-9.]*$', r'cpan$', r'cpanm$', r'perldoc$',
    # Ruby
    r'ruby[0-9.]*$', r'irb$', r'gem$', r'bundle$', r'rake$',
    # Node.js
    r'node$', r'nodejs$', r'npm$', r'npx$', r'yarn$', r'pnpm$',
    # Shell
    r'bash$', r'sh$', r'dash$', r'zsh$', r'fish$', r'ksh$', r'tcsh$',
    r'csh$', r'rc$', r'es$', r'xonsh$', r'nushell$',
    # Lua
    r'lua[0-9.]*$', r'luajit$', r' luarocks$',
    # PHP
    r'php[0-9]*$', r'php-fpm$', r'composer$', r'pear$', r'pecl$',
    # Java
    r'java$', r'javaw$', r'jre$', r'jvm$', r'jexec$',
    # Tcl/Tk
    r'tclsh', r'wish', r'tkcon$',
    # 其他
    r'awk$', r'gawk$', r'mawk$', r'nawk$', r'sed$', r'perl$',
    r'expect$', r'unbuffer$', r'script$', r'scriptreplay$',
]

COMPRESS_TOOL = [
    r'tar$', r'gtar$', r'bsdtar$', r'rar$', r'unrar$', r'zip$', r'unzip$',
    r'gzip$', r'gunzip$', r'gzexe$', r'zcat$', r'zdiff$', r'zgrep$',
    r'bzip2$', r'bunzip2$', r'bzcat$', r'bzdiff$', r'bzgrep$',
    r'xz$', r'unxz$', r'xzcat$', r'lzma$', r'unlzma$', r'lzcat$',
    r'lz4$', r'unlz4$', r'lz4cat$', r'zstd$', r'unzstd$', r'zstdcat$',
    r'7z$', r'7za$', r'7zr$', r'lha$', r'arc$', r'arj$', r'cabextract$',
    r'cpio$', r'pax$', r'dpkg-deb$', r'rpm2cpio$', r'rpmbuild$',
]

NETWORK_TOOL = [
    r'curl$', r'wget$', r'nc$', r'ncat$', r'netcat$', r'tcpdump$',
    r'tshark$', r'wireshark$', r'dumpcap$', r'ssh$', r'scp$', r'sftp$',
    r'rsync$', r'ftp$', r'lftp$', r'tftp$', r'ncftp$', r'inetd$',
    r'telnet$', r'openssl$', r's_client$', r's_server$', r'nmap$',
    r'hping3$', r' masscan$', r'zmap$', r'arp-scan$', r'ettercap$',
    r'dsniff$', r'tcpflow$', r'ngrep$', r'iptstate$', r'conntrack$',
]

TEXT_TOOL = [
    r'vim$', r'vi$', r'nvim$', r'emacs$', r'nano$', r'pico$', r'jed$',
    r'joe$', r'mcedit$', r'gedit$', r'kate$', r'leafpad$', r'mousepad$',
    r'awk$', r'gawk$', r'mawk$', r'nawk$', r'sed$', r'grep$', r'egrep$',
    r'fgrep$', r'rg$', r'ag$', r'pt$', r'ack$', r'jq$', r'yq$',
    r'cut$', r'paste$', r'join$', r'sort$', r'uniq$', r'wc$', r'head$',
    r'tail$', r'cat$', r'tac$', r'nl$', r'od$', r'hexdump$', r'xxd$',
    r'column$', r'csplit$', r'fold$', r'fmt$', r'pr$', r'expand$',
    r'unexpand$', r'center$', r'par$',
]

def get_level(name, checks):
    missing = []
    if checks.get('relro') != 'Full RELRO':
        missing.append('relro')
    if checks.get('canary') != 'Canary Found':
        missing.append('canary')
    if checks.get('nx') != 'NX enabled':
        missing.append('nx')
    if checks.get('pie') != 'PIE Enabled':
        missing.append('pie')
    if checks.get('fortify_source') != 'Yes':
        missing.append('fortify')

    if not missing:
        return 0

    basename = name.split('/')[-1]

    is_high = any(re.search(p, basename) for p in HIGH_RISK)
    is_dev = any(re.search(p, basename) for p in DEV_TOOL)
    is_doc = any(re.search(p, basename) for p in DOC_TOOL)
    is_interp = any(re.search(p, basename) for p in INTERPRETER)
    is_compress = any(re.search(p, basename) for p in COMPRESS_TOOL)
    is_network = any(re.search(p, basename) for p in NETWORK_TOOL)
    is_text = any(re.search(p, basename) for p in TEXT_TOOL)

    # 高危：特权/网络服务/系统服务
    if is_high:
        return 3

    # 解释器：仅缺失 pie/fortify 视为通过（运行时特性）
    if is_interp and len(missing) == 1 and missing[0] in ('pie', 'fortify'):
        return 0

    # 压缩工具：仅缺失 canary 为低危
    if is_compress and len(missing) == 1 and missing[0] == 'canary':
        return 1

    # 网络工具：仅缺失 canary/fortify 为中危
    if is_network and len(missing) <= 2 and all(m in ('canary', 'fortify') for m in missing):
        return 2

    # 文本工具：仅缺失 canary 为低危
    if is_text and len(missing) == 1 and missing[0] == 'canary':
        return 1

    # 开发工具：仅缺失 pie/fortify 视为通过
    if is_dev and len(missing) == 1 and missing[0] in ('pie', 'fortify'):
        return 0

    # 文档工具：仅缺失 canary 为低危
    if is_doc and len(missing) == 1 and missing[0] == 'canary':
        return 1

    # 缺失 >= 2 项为中危
    if len(missing) >= 2:
        return 2

    # 仅缺失 1 项为低危
    return 1


fail_items = []

for item in data:
    name = item['name']
    level = get_level(name, item['checks'])

    if level > 0:
        fail_items.append(f"{name} fail {level}")

if fail_items:
    for line in fail_items:
        out.write(line + '\n')
else:
    out.write(dirname + ' pass\n')

out.close()
PYEOF

  echo "结果已保存: $OUTPUT_FILE"
  cat "$OUTPUT_FILE"
}


echo "安装checksec"
pkginstall

echo "二进制加固验证"
binary_hardening_test

echo "结果转为lava result格式数据"
for i in "${!SCANDIR[@]}"; do
  scan_path="${SCANDIR[$i]}"
  res_file="${RESDIR[$i]}"

  echo "[*] 扫描目录: $scan_path"
  echo "[*] 结果存放路径: $res_file"
  binary_risk_lava "$res_file" "$scan_path"
done



