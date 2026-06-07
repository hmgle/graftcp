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
