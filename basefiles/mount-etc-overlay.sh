#!/bin/bash
# Mount /etc as overlay while preserving existing sub-overlays

set -e

ETC_OVERLAY_UPPER="/var/volatile/overlay/etc-root/upper"
ETC_OVERLAY_WORK="/var/volatile/overlay/etc-root/work"
MOUNT_INFO_FILE="/tmp/etc-overlay-mounts.txt"

# Check if /etc is already an overlay
if mount | grep -q "^overlay on /etc "; then
    echo "/etc is already an overlay"
    exit 0
fi

# Save existing /etc/* mounts info to file
echo "Saving existing /etc/* overlay mounts..."
mount | grep "on /etc/" > "$MOUNT_INFO_FILE" || true
cat "$MOUNT_INFO_FILE"

# Get mount points sorted by depth (deepest first for unmount)
MOUNTS_TO_UNMOUNT=$(awk '{print $3}' "$MOUNT_INFO_FILE" | awk '{print length, $0}' | sort -rn | cut -d' ' -f2-)

# Unmount all /etc/* mounts
echo "Unmounting..."
for mnt in $MOUNTS_TO_UNMOUNT; do
    echo "  umount $mnt"
    umount "$mnt" 2>/dev/null || true
done

# Mount /etc overlay
echo "Mounting /etc overlay..."
mkdir -p "$ETC_OVERLAY_UPPER" "$ETC_OVERLAY_WORK"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$ETC_OVERLAY_UPPER,workdir=$ETC_OVERLAY_WORK" /etc

# Remount previous mounts (shallowest first)
echo "Remounting previous mounts..."
MOUNTS_TO_REMOUNT=$(awk '{print $3}' "$MOUNT_INFO_FILE" | awk '{print length, $0}' | sort -n | cut -d' ' -f2-)
for mnt in $MOUNTS_TO_REMOUNT; do
    line=$(grep "on $mnt " "$MOUNT_INFO_FILE")
    type=$(echo "$line" | awk '{print $5}')
    opts=$(echo "$line" | sed 's/.*(\(.*\))/\1/')

    echo "  mount -t $type ... -o $opts $mnt"
    mount -t "$type" "$type" -o "$opts" "$mnt" 2>/dev/null || echo "    skipped or failed"
done

rm -f "$MOUNT_INFO_FILE"

echo ""
echo "Done. Current /etc mounts:"
mount | grep "/etc"
