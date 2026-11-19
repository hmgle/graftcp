#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: scripts/build-release-packages.sh VERSION TARGET PACKAGE_ARCH [CROSS_COMPILE]}"
target="${2:?usage: scripts/build-release-packages.sh VERSION TARGET PACKAGE_ARCH [CROSS_COMPILE]}"
package_arch="${3:?usage: scripts/build-release-packages.sh VERSION TARGET PACKAGE_ARCH [CROSS_COMPILE]}"
cross_compile="${4:-}"

package_version="${version#v}"
dist_dir="${DIST_DIR:-dist}"
pkgroot="build/package-root"

rm -rf "$pkgroot" "$dist_dir"
mkdir -p "$pkgroot/usr/bin" "$pkgroot/usr/share/doc/graftcp/examples" "$dist_dir"

make clean
if [[ -n "$cross_compile" ]]; then
	make VERSION="$version" CROSS_COMPILE="$cross_compile" all
else
	make VERSION="$version" all
fi

binary="local/graftcp"
elf_header="$(LC_ALL=C readelf -h "$binary")"
elf_class="$(sed -n 's/^[[:space:]]*Class:[[:space:]]*//p' <<< "$elf_header")"
elf_machine="$(sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' <<< "$elf_header")"
case "$target" in
	linux-amd64)
		expected_class='ELF64'
		expected_machine='Advanced Micro Devices X86-64'
		;;
	linux-arm64)
		expected_class='ELF64'
		expected_machine='AArch64'
		;;
	linux-armv7)
		expected_class='ELF32'
		expected_machine='ARM'
		;;
	linux-386)
		expected_class='ELF32'
		expected_machine='Intel 80386'
		;;
	*)
		echo "unsupported release target: $target" >&2
		exit 1
		;;
esac
if [[ "$elf_class" != "$expected_class" || "$elf_machine" != "$expected_machine" ]]; then
	echo "built $target package contains an unexpected binary: $elf_class $elf_machine" >&2
	exit 1
fi

install -m 0755 local/graftcp "$pkgroot/usr/bin/graftcp"
ln -s graftcp "$pkgroot/usr/bin/mgraftcp"
install -m 0644 COPYING README.md README.zh-CN.md CHANGELOG.md "$pkgroot/usr/share/doc/graftcp/"
install -m 0644 example-graftcp.conf "$pkgroot/usr/share/doc/graftcp/examples/graftcp.conf"
install -m 0644 example-mgraftcp.conf "$pkgroot/usr/share/doc/graftcp/examples/mgraftcp.conf"
install -m 0644 example-blacklist-ip.txt "$pkgroot/usr/share/doc/graftcp/examples/blacklist-ip.txt"
install -m 0644 example-whitelist-ip.txt "$pkgroot/usr/share/doc/graftcp/examples/whitelist-ip.txt"

tar -C "$pkgroot" -czf "$dist_dir/graftcp_${version}_${target}.tar.gz" .

PACKAGE_VERSION="$package_version" PACKAGE_ARCH="$package_arch" \
	nfpm package --config packaging/nfpm.yaml --packager deb \
	--target "$dist_dir/graftcp_${version}_${target}.deb"

PACKAGE_VERSION="$package_version" PACKAGE_ARCH="$package_arch" \
	nfpm package --config packaging/nfpm.yaml --packager rpm \
	--target "$dist_dir/graftcp_${version}_${target}.rpm"
