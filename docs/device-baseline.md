# Device Boot Baseline

Observed from the connected device over adb root:

- product: `zorn`
- Android release: `15`
- kernel release string: `6.1.75-android14-11-...`
- boot partition size: `100663296` bytes
- init_boot partition size: `8388608` bytes
- vendor_boot partition size: `100663296` bytes
- boot header version: `4`
- vendor boot magic: `VNDRBOOT`

Implication:

- do not treat a hand-made raw `boot.img` from CI as the preferred flash path
- preserve the existing boot chain structure
- use AnyKernel3 as the primary delivery path while iterating on the kernel
