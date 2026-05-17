#!/system/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  exec /system/bin/sh
fi

exec /system/bin/sh -c "$*"
