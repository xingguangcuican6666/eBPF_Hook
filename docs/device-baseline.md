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

- ABK should stay responsible for bootable output generation
- `eBPF_Hook` should only inject kernel tree changes
- regression testing must be done level-by-level (`L0` -> `L4`)
