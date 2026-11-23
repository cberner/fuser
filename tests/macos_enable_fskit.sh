#!/usr/bin/env bash
# Enable macFUSE's FSKit file system extensions without System Settings, for CI.
#
# FSKit keeps the enabled modules in a per-user plist that System Settings writes; fskitd
# reads it when it starts. This is not a supported interface and may break with macOS updates.

set -euo pipefail

app=/Library/Filesystems/macfuse.fs/Contents/Resources/macfuse.app
lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
modules="io.macfuse.app.fsmodule.macfuse-local io.macfuse.app.fsmodule.macfuse"
dir="$HOME/Library/Group Containers/group.com.apple.fskit.settings"
plist="$dir/enabledModules.plist"

# Without this, PluginKit may not find the extensions inside macfuse.app
"$lsregister" -f "$app"
for module in $modules; do
  pluginkit -m -A -D -i "$module" | grep -q "$module"
done

mkdir -p "$dir"
if ! /usr/libexec/PlistBuddy -c Print "$plist" 2>/dev/null | head -1 | grep -q "Array {"; then
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
    '<plist version="1.0">' '<array/>' '</plist>' > "$plist"
fi
for module in $modules; do
  /usr/libexec/PlistBuddy -c Print "$plist" | grep -Fqx "    $module" \
    || /usr/libexec/PlistBuddy -c "Add : string $module" "$plist"
done
plutil -lint "$plist"

# fskitd only reads the plist on start
sudo killall fskitd || true
killall fskit_agent 2>/dev/null || true
killall extensionkitservice 2>/dev/null || true
sleep 3
