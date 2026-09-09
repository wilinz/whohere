#!/usr/bin/env bash
# 构建 whohere + luci-app-whohere 两个 ipk
# 依赖: cargo-zigbuild + zig(交叉静态 musl), tar(ustar)
#
# 可用环境变量:
#   TARGET   rust 目标三元组   (默认 x86_64-unknown-linux-musl)
#   ARCH     opkg 架构名       (默认 x86_64)
#   VERSION  版本号            (默认取自 CONTROL/control)
#   BUILDSTD 1=用 nightly -Z build-std 编 tier-3 目标(如 mips) (默认 0)
#   BUILD_ENGINE 1/0  是否编译+打包引擎包 (默认 1)
#   BUILD_LUCI   1/0  是否打包 LuCI 包(架构无关) (默认 1)
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
OUT="$ROOT/out"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
ARCH="${ARCH:-x86_64}"
VERSION="${VERSION:-}"
BUILDSTD="${BUILDSTD:-0}"
BUILD_ENGINE="${BUILD_ENGINE:-1}"
BUILD_LUCI="${BUILD_LUCI:-1}"
export COPYFILE_DISABLE=1   # 禁 macOS AppleDouble (._*)

# 注入版本号到 control(CI 用 tag 覆盖)
if [ -n "$VERSION" ]; then
	for c in pkg/whohere/CONTROL/control pkg/luci-app-whohere/CONTROL/control; do
		sed -i.bak "s/^Version:.*/Version: $VERSION/" "$c" && rm -f "$c.bak"
	done
fi

# tar 参数: GNU(Linux CI) 与 BSD(macOS) 语法不同, 分别处理; 统一 ustar + root 属主
if tar --version 2>/dev/null | grep -qi "gnu"; then
	TARFMT=(--format=ustar --owner=0 --group=0 --numeric-owner)
else
	TARFMT=(--format ustar --uid 0 --gid 0 --numeric-owner)
fi

# ustar 格式 + root 属主, 避免 opkg 读不了 pax 扩展头
tar_ustar() {  # <src_dir> <out.tar.gz>
	( cd "$1" && tar "${TARFMT[@]}" -czf "$2" ./* )
}

build_ipk() {  # <pkgdir> <arch>
	local pkgdir="$1" arch="$2"
	local name ver tmp ipk
	name="$(awk -F': ' '/^Package:/{print $2}' "$pkgdir/CONTROL/control")"
	ver="$(awk -F': ' '/^Version:/{print $2}' "$pkgdir/CONTROL/control")"
	# 架构必须写进 control, 只改文件名没用 —— opkg 认的是 control 里的
	# Architecture 字段, 不一致会报 "incompatible with the architectures configured"
	sed -i.bak "s|^Architecture:.*|Architecture: $arch|" "$pkgdir/CONTROL/control"
	rm -f "$pkgdir/CONTROL/control.bak"
	tmp="$(mktemp -d)"

	printf '2.0\n' > "$tmp/debian-binary"
	chmod 0644 "$pkgdir/CONTROL/control"
	[ -f "$pkgdir/CONTROL/conffiles" ] && chmod 0644 "$pkgdir/CONTROL/conffiles"
	for s in preinst postinst prerm postrm; do
		[ -f "$pkgdir/CONTROL/$s" ] && chmod 0755 "$pkgdir/CONTROL/$s"
	done
	tar_ustar "$pkgdir/CONTROL" "$tmp/control.tar.gz"
	tar_ustar "$pkgdir/data"    "$tmp/data.tar.gz"

	mkdir -p "$OUT"
	ipk="$OUT/${name}_${ver}_${arch}.ipk"
	rm -f "$ipk"
	# OpenWrt 的 .ipk = 三个成员的 gzip tar (opkg-utils ipkg-build 的产物), 不是 ar!
	( cd "$tmp" && tar "${TARFMT[@]}" -czf "$ipk" ./debian-binary ./control.tar.gz ./data.tar.gz )
	rm -rf "$tmp"
	echo "    -> $ipk"
}

if [ "$BUILD_ENGINE" = "1" ]; then
	echo "==> 交叉编译 rust 引擎 (target=$TARGET, arch=$ARCH, buildstd=$BUILDSTD)"
	if [ "${TARGET%muslabi64}" != "$TARGET" ]; then
		# mips64(如 octeon, N64 ABI): cargo-zigbuild 把 target 发成 zig 不认的
		# `mips64-linux-muslabi64`(UnknownApplicationBinaryInterface), 无法用 zigbuild。
		# 改为裸 zig cc 当 linker, zig target 用 `mips64-linux-musl`(N64 默认);
		# musl 无 libgcc_s, 把 rust 传的 -lgcc_s 换成 zig 自带 -lunwind(供 std 回溯符号)。
		ZT="$(echo "$TARGET" | sed 's/-unknown-linux-muslabi64$/-linux-musl/')"  # mips64->mips64-linux-musl
		WRAP="$(mktemp -d)"
		cat > "$WRAP/zcc.sh" <<EOF
#!/bin/sh
args=""
for a in "\$@"; do [ "\$a" = "-lgcc_s" ] && a="-lunwind"; args="\$args \"\$a\""; done
eval exec zig cc -target $ZT \$args
EOF
		printf '#!/bin/sh\nexec zig ar "$@"\n' > "$WRAP/zar.sh"
		chmod +x "$WRAP"/*.sh
		VUP="$(echo "$TARGET" | tr 'a-z-' 'A-Z_')"   # CARGO_TARGET_<T>_LINKER 用的大写形式
		( cd whohere-rs && \
			env "CC_${TARGET//-/_}=$WRAP/zcc.sh" "AR_${TARGET//-/_}=$WRAP/zar.sh" \
			"CARGO_TARGET_${VUP}_LINKER=$WRAP/zcc.sh" \
			cargo +nightly build --release -Z build-std=std,panic_abort --target "$TARGET" )
		rm -rf "$WRAP"
	elif [ "$BUILDSTD" = "1" ]; then
		# tier-3 mips(24kc 无 FPU): rust 按 soft-float 编, 但 zig 的 mipsel-linux-musl
		# 默认 hard-float(-mdouble-float), 两者链接时 ABI 冲突。用 link-arg 把 zig cc
		# 的 cpu 设成 soft_float, 让 zig 自带的 libc/compiler_rt 也编成软浮点。
		EXTRA_RUSTFLAGS=""
		case "$TARGET" in
			mips*-unknown-linux-musl) EXTRA_RUSTFLAGS="-C link-arg=-mcpu=mips32r2+soft_float" ;;
		esac
		( cd whohere-rs && RUSTFLAGS="${RUSTFLAGS:-} $EXTRA_RUSTFLAGS" cargo +nightly zigbuild --release \
			-Z build-std=std,panic_abort --target "$TARGET" )
	else
		( cd whohere-rs && cargo zigbuild --release --target "$TARGET" )
	fi
	mkdir -p pkg/whohere/data/usr/bin
	cp "whohere-rs/target/$TARGET/release/whohere" pkg/whohere/data/usr/bin/whohere
	chmod +x pkg/whohere/data/usr/bin/whohere \
		pkg/whohere/data/etc/init.d/whohere \
		pkg/whohere/data/usr/libexec/rpcd/whohere \
		pkg/whohere/data/usr/share/whohere/dhcp-hook.sh \
		pkg/whohere/data/usr/share/whohere/update-oui.sh \
		pkg/whohere/data/usr/share/whohere/update-rules.sh
	echo "==> 打包引擎"
	build_ipk pkg/whohere "$ARCH"
fi

if [ "$BUILD_LUCI" = "1" ]; then
	echo "==> 打包 LuCI (all)"
	build_ipk pkg/luci-app-whohere all
fi

echo "==> 完成"
ls -la "$OUT"
