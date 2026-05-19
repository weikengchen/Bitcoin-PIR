{
  description = "BitcoinPIR — hermetic build environment for Tier 3 UKI reproducibility (sub-task 5 of docs/PHASE3_SLICE3_REPRO_PLAN.md)";

  # Pin nixpkgs + rust-overlay to specific revisions so two operators on
  # different machines get bit-identical toolchains. The flake.lock file
  # commits the resolved revisions; running `nix flake update` is an
  # explicit, audit-able operation.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ rust-overlay.overlays.default ];
    };

    # Match rust-toolchain.toml's pinned channel (1.94.1 stable).
    # Both operators end up with byte-identical rustc binaries.
    rustToolchain = pkgs.rust-bin.stable."1.94.1".default;

    # Intel HEXL — x86_64 NTT/eltwise acceleration for the onionpir C++
    # engine (linked when ONIONPIR_USE_HEXL is defined, i.e. USE_HEXL=ON —
    # the crate's x86_64 default since rev 7ea020a). nixpkgs has no `hexl`
    # package, so build it here. HEXL 1.2.6 does `find_package(CpuFeatures
    # CONFIG)` and only FetchContent-downloads google/cpu_features if that
    # misses — passing nixpkgs' cpu_features makes the HEXL build fully
    # hermetic (no network). HEXL_BENCHMARK/HEXL_TESTING OFF likewise skip
    # the google-benchmark / gtest FetchContent. The result ships
    # lib/cmake/hexl-1.2.6/HEXLConfig.cmake, so the onionpir build's
    # `find_package(HEXL CONFIG)` resolves it (see buildInputs + postPatch).
    hexl = pkgs.stdenv.mkDerivation {
      pname = "hexl";
      version = "1.2.6";
      src = pkgs.fetchFromGitHub {
        owner = "intel";
        repo = "hexl";
        rev = "v1.2.6";
        hash = "sha256-9DWQMmbvwl/UVyllNoixjJJsd7ksFztwKZ8gFlIBg+U=";
      };
      nativeBuildInputs = [ pkgs.cmake ];
      # cpu_features ships its CMake config package in the `dev` output;
      # buildInputs propagation puts it on CMAKE_PREFIX_PATH so HEXL's
      # `find_package(CpuFeatures CONFIG)` resolves it instead of fetching.
      buildInputs = [ pkgs.cpu_features ];
      cmakeFlags = [
        # nixpkgs' cmake hook sets CMAKE_INSTALL_INCLUDEDIR to an absolute
        # path; HEXL's header install does
        #   install(DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
        # which then double-prefixes ($out/nix/store/...-hexl/include) and
        # leaves HEXL::hexl's INTERFACE_INCLUDE_DIRECTORIES pointing at a
        # non-existent $out/include. A relative includedir lands the
        # headers at $out/include, where the exported config expects them.
        "-DCMAKE_INSTALL_INCLUDEDIR=include"
        "-DHEXL_BENCHMARK=OFF"
        "-DHEXL_TESTING=OFF"
        "-DHEXL_SHARED_LIB=OFF"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
      ];
    };

  in {
    # ─── packages.unified-server ───────────────────────────────────────
    # Phase 2 of sub-task 5: build inside Nix's sandbox so the source
    # gets content-addressed into /nix/store/<hash>-source/. Two operators
    # cloning to different host paths converge to the same /nix/store
    # path → C++ __FILE__ macros in OnionPIR's CMake-built libonionpir.a
    # embed identical strings → cross-path determinism closes (the gap
    # the convention-based recipe couldn't reach).
    #
    # Use: `nix build .#unified-server` → ./result/bin/unified_server
    packages.${system} = {
      # ─── packages.tier3-uki ────────────────────────────────────────
      # Production Tier 3 UKI for pir2 (weikeng2 — VPSBG, SEV-SNP).
      #
      # Assembles the whole UKI inside Nix — VPSBG kernel + initramfs +
      # cmdline objcopy'd into systemd's EFI stub — embedding the exact
      # reproducible `unified_server` from packages.unified-server. This
      # is the flake counterpart of scripts/build_uki_tier3.sh: that
      # recipe bakes a *system-linked* binary via dracut; this one
      # bundles the full /nix/store closure via makeInitrdNG, so the
      # baked-in binary is bit-identical to `nix build .#unified-server`
      # (hence byte-identical to what pir1 runs).
      #
      #   nix build --impure .#tier3-uki    # on pir-hetzner, as root
      #   → ./result/bpir-tier3.efi
      #
      # ── IMPURITY: the VPSBG kernel ─────────────────────────────────
      # pir2's measured-boot + SEV-SNP chain is validated ONLY for the
      # Ubuntu-25.04-plucky-backport kernel 7.0.0-15-generic. A Nix
      # kernel would change the launch MEASUREMENT and is not validated
      # for VPSBG SEV-SNP. So the kernel image + its module tree are
      # sourced from the BUILD HOST's filesystem (/boot, /lib/modules)
      # via `builtins.path` — a deliberate, controlled break of flake
      # hermeticity. Consequences:
      #   - `nix build` MUST be passed `--impure` (else eval fails:
      #     "access to absolute path '/boot/...' is forbidden").
      #   - the build MUST run on the Hetzner UKI build host — the only
      #     machine with this kernel installed (CLAUDE.md "Hetzner — UKI
      #     build host"), as root (/boot/vmlinuz-* is mode 0600).
      # The impurity is confined to *where the kernel comes from*; the
      # result stays content-addressed and reproducible given the same
      # kernel + module tree + flake revision.
      tier3-uki = let
        # Kernel version. Keep in sync with the path literals below
        # (Nix path literals are not cleanly string-interpolatable).
        kver = "7.0.0-15-generic";

        # VPSBG-validated kernel image + module tree, content-addressed
        # from the build host's filesystem. See the IMPURITY note above.
        vpsbgKernelImage = builtins.path {
          path = /boot/vmlinuz-7.0.0-15-generic;
          name = "vmlinuz-7.0.0-15-generic";
        };
        vpsbgModulesSrc = builtins.path {
          path = /lib/modules/7.0.0-15-generic;
          name = "vpsbg-modules-7.0.0-15-generic";
        };

        unifiedServer = self.packages.${system}.unified-server;

        # cloudflared — the official statically-linked release binary.
        # nixpkgs' cloudflared is a *dynamically* linked Go build with
        # no RUNPATH: it resolves libc against a system /lib the Tier 3
        # initramfs does not have, and patchelf'ing a RUNPATH onto a Go
        # binary corrupts it (verified: segfault, exit 139). The
        # official cloudflared-linux-amd64 asset is fully static (no ELF
        # interpreter) — zero library resolution, nothing to bundle —
        # which is exactly what the proven dracut v16 recipe ships.
        # Pinned by content hash, so `fetchurl` stays a hermetic
        # fixed-output derivation (this part needs no `--impure`).
        cloudflaredStatic = pkgs.fetchurl {
          url = "https://github.com/cloudflare/cloudflared/releases/download/2026.3.0/cloudflared-linux-amd64";
          hash = "sha256-Sp5Q5tbXmOkPzQGTMVGpC/ft2ZoKVcKK0Y8uFiY6XDA=";
        };

        # Boot scripts — copied verbatim from scripts/dracut/97bpir-tier3-init/.
        # NOT patched: the same files drive the proven dracut recipe
        # (build_uki_tier3.sh). Instead, every binary the scripts invoke
        # is placed below at the absolute path the script expects, so
        # the scripts stay byte-identical across both recipes.
        bpirInitScript   = ./scripts/dracut/97bpir-tier3-init/bpir-tier3-init.sh;
        cloudflaredRun   = ./scripts/dracut/97bpir-tier3-init/cloudflared-run.sh;
        unifiedServerRun = ./scripts/dracut/97bpir-tier3-init/unified-server-run.sh;

        # ── Minimal SEV-SNP kernel-module subset ─────────────────────
        # The 7.0.0-15 kernel has virtio_net / virtio_pci / virtio_blk
        # and ext4 built IN (confirmed in modules.builtin), so the only
        # loadable modules a Tier 3 boot needs are the SEV-SNP guest
        # stack: ccp, sev-guest, tsm_report. Their dependency closure is
        # exactly those three (modules.dep: ccp→∅, sev-guest→tsm_report,
        # tsm_report→∅). This mirrors the --add-drivers set + two-gate
        # SEV validation of build_uki_tier3.sh.
        #
        # The host module tree nests the real .ko files one level deep
        # (its modules.dep entries are prefixed "7.0.0-15-generic/..."),
        # so each module is resolved by name with `find`, normalised
        # into a standard kernel/... layout, and depmod regenerates
        # clean metadata.
        modulesSubset = pkgs.runCommand "bpir-tier3-modules-${kver}" {
          nativeBuildInputs = [ pkgs.kmod ];
        } ''
          set -euo pipefail
          dst="$out/lib/modules/${kver}"
          mkdir -p "$dst/kernel/drivers/crypto/ccp" \
                   "$dst/kernel/drivers/virt/coco/sev-guest" \
                   "$dst/kernel/drivers/virt/coco/guest"

          copy_mod() {
            # $1 = module basename, $2 = destination kernel/ subdir.
            local ko
            ko=$(find ${vpsbgModulesSrc} -name "$1.ko.zst" -print -quit)
            [ -n "$ko" ] || { echo "FATAL: $1.ko.zst not in module tree" >&2; exit 1; }
            cp "$ko" "$dst/$2/"
            echo "bundled module: $1  <-  $ko"
          }
          copy_mod ccp        kernel/drivers/crypto/ccp
          copy_mod sev-guest  kernel/drivers/virt/coco/sev-guest
          copy_mod tsm_report kernel/drivers/virt/coco/guest

          # depmod inputs: the built-in module list + ordering hints, so
          # a runtime `modprobe ext4` / `modprobe virtio_net` resolves
          # as builtin (exit 0) rather than "not found".
          for f in modules.builtin modules.builtin.modinfo modules.order; do
            if [ -e "${vpsbgModulesSrc}/$f" ]; then
              cp "${vpsbgModulesSrc}/$f" "$dst/"
            fi
          done

          depmod -b "$out" "${kver}"

          # ── SEV validation gate (mirrors build_uki_tier3.sh) ──
          for mod in ccp sev-guest tsm_report; do
            grep -qF "/$mod.ko" "$dst/modules.dep" \
              || { echo "FATAL: $mod absent from generated modules.dep" >&2; exit 1; }
          done
          echo "SEV-SNP modules confirmed in modules.dep: ccp sev-guest tsm_report"
        '';

        # ── Initramfs ────────────────────────────────────────────────
        # makeInitrdNG is deliberately NOT used. Its make-initrd-ng tool
        # resolves a binary's shared libraries via that binary's own
        # RUNPATH only — it does NOT walk the Nix store closure (the
        # tool's own source notes glibc is unreachable that way). Go's
        # cloudflared and glibc's own libs carry no usable RUNPATH, so
        # makeInitrdNG silently drops them ("Couldn't satisfy dependency
        # libc.so.6 …") and the initramfs comes out unrunnable (~17 MB).
        #
        # Instead: take the FULL runtime closure via closureInfo, copy
        # every store path in verbatim, lay out the FHS-ish symlink tree
        # the (dracut-shared, unmodified) boot scripts expect, and roll a
        # reproducible newc cpio. Every bundled binary resolves its
        # interpreter + libraries through absolute /nix/store paths, all
        # of which are present.
        initrdClosure = pkgs.closureInfo {
          rootPaths = [
            pkgs.busybox pkgs.iproute2 pkgs.util-linux pkgs.kmod pkgs.runit
            unifiedServer modulesSubset
          ];
        };

        initrd = pkgs.runCommand "bpir-tier3-initrd" {
          nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];
        } ''
          set -euo pipefail
          root=root
          mkdir -p "$root"

          # 1. The complete runtime closure → /nix/store/<hash>.
          mkdir -p "$root/nix/store"
          cp -a $(cat ${initrdClosure}/store-paths) "$root/nix/store/"

          # 2. Kernel pseudo-fs mount points — bpir-tier3-init.sh mounts
          #    proc/sysfs/devtmpfs onto these without mkdir'ing them.
          #    (CONFIG_DEVTMPFS_MOUNT=y → kernel populates /dev itself.)
          mkdir -p "$root/proc" "$root/sys" "$root/dev" "$root/run" "$root/tmp"

          # 3. /bin → busybox applet dir: /bin/{sh,mount,ip,sleep,mkdir,
          #    ln,cat,grep,ls,reboot,nc,...}. /bin/sh backs every
          #    #!/bin/sh (the rdinit takeover + the runit `run` scripts).
          ln -s ${pkgs.busybox}/bin "$root/bin"

          # 4. Tools where the busybox applet is not good enough, in
          #    /usr/bin so PATH (/usr/local/bin:/usr/bin:/usr/sbin:/sbin:
          #    /bin) finds them first: kmod modprobe/lsmod (loads the
          #    .ko.zst SEV modules), iproute2 ip (route ... onlink),
          #    util-linux mount/blkid (rootfs LABEL= / ext4 / --bind).
          mkdir -p "$root/usr/bin" "$root/usr/local/bin" "$root/sbin" \
                   "$root/etc/sv/cloudflared" "$root/etc/sv/unified_server" \
                   "$root/lib"
          ln -s ${pkgs.kmod}/bin/modprobe           "$root/usr/bin/modprobe"
          ln -s ${pkgs.kmod}/bin/lsmod              "$root/usr/bin/lsmod"
          ln -s ${pkgs.iproute2}/bin/ip             "$root/usr/bin/ip"
          ln -s ${pkgs.util-linux}/bin/mount        "$root/usr/bin/mount"
          ln -s ${pkgs.util-linux}/bin/blkid        "$root/usr/bin/blkid"
          ln -s ${pkgs.runit}/bin/runsvdir          "$root/usr/bin/runsvdir"
          ln -s ${pkgs.runit}/bin/runsv             "$root/usr/bin/runsv"
          ln -s ${pkgs.runit}/bin/sv                "$root/usr/bin/sv"
          ln -s ${pkgs.runit}/bin/chpst             "$root/usr/bin/chpst"

          # 5. The two long-lived services + rdinit takeover + runit
          #    `run` scripts, at the absolute paths the scripts use.
          #    unified_server is the reproducible Nix build (== pir1).
          # cloudflared: the static release binary, copied in directly
          # (no closure, no interpreter). unified_server: the Nix build
          # — symlinked so makeInitrdNG-style closure copying applies.
          install -m0755 ${cloudflaredStatic}      "$root/usr/local/bin/cloudflared"
          ln -s ${unifiedServer}/bin/unified_server "$root/usr/local/bin/unified_server"
          # The three scripts are COPIED with an explicit +x mode (not
          # symlinked into the store): the repo files' executable bits
          # are inconsistent — unified-server-run.sh is not +x, and a
          # 0444 store symlink target makes runsv fail the service with
          # "unable to start ./run: access denied" (caught in QEMU). The
          # dracut recipe masks this by chmod'ing its module dir.
          install -m0755 ${bpirInitScript}   "$root/sbin/bpir-tier3-init"
          install -m0755 ${cloudflaredRun}   "$root/etc/sv/cloudflared/run"
          install -m0755 ${unifiedServerRun} "$root/etc/sv/unified_server/run"

          # 6. SEV-SNP module subset → /lib/modules/<kver>/ for modprobe.
          ln -s ${modulesSubset}/lib/modules "$root/lib/modules"

          # 7. Reproducible newc cpio + gzip (kernel: CONFIG_RD_GZIP=y).
          mkdir -p "$out"
          find "$root" -exec touch -h -d @1 {} +
          ( cd "$root" && find . -print0 | sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | gzip -9 -n ) > "$out/initrd"
          echo "initrd size: $(du -h "$out/initrd" | cut -f1)" \
               "($(wc -l < ${initrdClosure}/store-paths) store paths)"
        '';

      in pkgs.runCommand "bpir-tier3-uki" {
        # objcopy assembles the UKI: it appends .osrel / .cmdline /
        # .linux / .initrd PE sections to systemd's linuxx64.efi.stub.
        # (ukify would do the same, but nixpkgs at this pin has no
        # `ukify` attr and `systemdUkify` is unreliable — objcopy is
        # the documented pre-ukify recipe and needs no Python.)
        nativeBuildInputs = with pkgs; [ binutils ];
        passthru = { inherit initrd modulesSubset; kernel = vpsbgKernelImage; };
      } ''
        set -euo pipefail
        STUB=${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub
        [ -f "$STUB" ] || { echo "ERROR: EFI stub not found at $STUB" >&2; exit 1; }

        KERNEL=${vpsbgKernelImage}
        INITRD=${initrd}/initrd

        # cmdline — byte-identical to build_uki_tier3.sh's proven v16
        # cmdline. rdinit= makes the kernel exec our PID 1 takeover
        # straight from the initramfs (no rootfs pivot).
        printf '%s' \
          "rdinit=/sbin/bpir-tier3-init console=ttyS0,115200 console=tty1 quiet loglevel=3" \
          > cmdline
        printf 'NAME="bpir"\nID=bpir\nVERSION_ID="tier3-v17"\nPRETTY_NAME="BitcoinPIR Tier 3 (v17)"\n' \
          > os-release

        # ── PE section VMAs ────────────────────────────────────────
        # objcopy-appended sections must sit ABOVE the stub's own PE
        # image: VMA ≥ ImageBase, past SizeOfImage. Otherwise BFD
        # truncates the 32-bit RVA ("section below image base") and the
        # UKI is unbootable. The nixpkgs systemd stub's ImageBase is NOT
        # a round number (and shifts with systemd bumps), so read
        # ImageBase + SizeOfImage off the stub and compute from there.
        # awk has no `exit` (reads all of objdump's output) so the pipe
        # never SIGPIPEs the producer under `set -o pipefail`.
        imagebase=$(( 0x$(objdump -p "$STUB" | awk '/^ImageBase/    {v=$2} END {print v}') ))
        sizeofimage=$(( 0x$(objdump -p "$STUB" | awk '/^SizeOfImage/ {v=$2} END {print v}') ))
        mib=$(( 1024 * 1024 ))
        stub_end=$(( imagebase + sizeofimage ))
        # First MiB-aligned VMA above the stub image, then 1 MiB gaps
        # (.osrel/.cmdline are tiny) and a 64 MiB gap for the kernel.
        osrel_vma=$(( ( stub_end + mib - 1 ) / mib * mib ))
        cmdline_vma=$(( osrel_vma   + mib ))
        linux_vma=$((   cmdline_vma + mib ))
        initrd_vma=$((  linux_vma + 64 * mib ))

        linux_sz=$(stat -c %s "$KERNEL")
        if [ "$linux_sz" -ge $(( 64 * mib )) ]; then
          echo "ERROR: kernel ($linux_sz bytes) exceeds the 64 MiB .linux gap" >&2
          exit 1
        fi
        echo "stub: ImageBase=$(printf '0x%x' "$imagebase") SizeOfImage=$(printf '0x%x' "$sizeofimage")"
        echo "VMAs: osrel=$(printf '0x%x' "$osrel_vma") cmdline=$(printf '0x%x' "$cmdline_vma") linux=$(printf '0x%x' "$linux_vma") initrd=$(printf '0x%x' "$initrd_vma")"

        mkdir -p "$out"
        objcopy \
          --add-section .osrel=os-release  --change-section-vma .osrel="$osrel_vma" \
          --add-section .cmdline=cmdline   --change-section-vma .cmdline="$cmdline_vma" \
          --add-section .linux="$KERNEL"   --change-section-vma .linux="$linux_vma" \
          --add-section .initrd="$INITRD"  --change-section-vma .initrd="$initrd_vma" \
          "$STUB" "$out/bpir-tier3.efi" 2> objcopy.err \
            || { cat objcopy.err >&2; echo "ERROR: objcopy failed" >&2; exit 1; }

        # ── Post-build validation ──────────────────────────────────
        # objcopy emits "section below image base" as a WARNING (exit 0
        # still), so inspect its stderr explicitly.
        if [ -s objcopy.err ]; then
          echo "── objcopy warnings ──"; cat objcopy.err
          if grep -q 'below image base' objcopy.err; then
            echo "ERROR: objcopy placed a section below the PE image base" >&2
            exit 1
          fi
        fi
        # (here-string, not a pipe, to avoid SIGPIPE under pipefail.)
        sections=$(objdump -h "$out/bpir-tier3.efi")
        echo "── UKI PE sections ──"
        echo "$sections"
        for s in .osrel .cmdline .linux .initrd; do
          grep -q -- "$s" <<< "$sections" \
            || { echo "ERROR: section $s missing from UKI" >&2; exit 1; }
        done
        # SizeOfImage must cover .initrd's RVA end, else the firmware
        # will not map the initramfs into memory and the boot dies.
        out_soi=$(( 0x$(objdump -p "$out/bpir-tier3.efi" | awk '/^SizeOfImage/ {v=$2} END {print v}') ))
        initrd_sz=$(stat -c %s "$INITRD")
        initrd_end_rva=$(( initrd_vma - imagebase + initrd_sz ))
        if [ "$out_soi" -lt "$initrd_end_rva" ]; then
          echo "ERROR: UKI SizeOfImage ($(printf '0x%x' "$out_soi")) does not cover .initrd end ($(printf '0x%x' "$initrd_end_rva"))" >&2
          exit 1
        fi
        echo "SizeOfImage=$(printf '0x%x' "$out_soi") covers .initrd end=$(printf '0x%x' "$initrd_end_rva") — OK"

        sha256sum "$out/bpir-tier3.efi" | tee "$out/bpir-tier3.efi.sha256"
        echo
        echo "kernel:         $KERNEL ($linux_sz bytes)"
        echo "initrd:         $INITRD"
        echo "unified_server: ${unifiedServer}/bin/unified_server"
      '';

      unified-server = pkgs.rustPlatform.buildRustPackage {
        pname = "unified-server";
        version = "0.1.0";
        src = ./.;

        # Cargo.lock is the source of truth for crate versions; outputHashes
        # provide content hashes for git deps (cargo vendor's git fetch is
        # non-deterministic without these). Initial values are lib.fakeHash;
        # first `nix build` will fail with the actual hash to substitute.
        cargoLock = {
          lockFile = ./Cargo.lock;
          # Content hashes for the git deps in Cargo.lock. The keys MUST
          # be exactly the set of git dependencies in Cargo.lock — a
          # stale key ("a hash was specified for X, but there is no
          # corresponding git dependency") and a missing one both fail
          # evaluation. Re-capture whenever a git rev or the dep set
          # changes: set the entry to the all-A fake hash, run
          # `nix build`, substitute the hash from the mismatch error.
          # Note: the onionpir crate is SEAL-free and submodule-free —
          # its hash covers just the rust/onionpir/ crate tree (Rust src
          # + the bundled cpp/ C++ engine + CMakeLists.txt).
          #
          # 2026-05-18 re-sync: dropped `alf-nt` (HarmonyPIR's PRP
          # backend no longer depends on the ALF crate); added `arc`
          # (new git dep); `onionpir-0.1.0` → `onionpir-0.2.0`.
          # 2026-05-19 re-pin: onionpir aa7710d → c7ed905 → 7ea020a — the
          # self-contained-crate restructure, then the HEXL / -march
          # detection fix. New rev → new content hash (fake-hash cycle).
          outputHashes = {
            "arc-0.1.0"        = "sha256-tUyvnyJoNTlrXpudIZ3Er6Mqj8zmltBtY06kF9P6hp0=";
            "fastprp-0.1.0"    = "sha256-GVTeA1yBdpOj0GHcKTqQZz+1+AvV+tBkvUewTnNSlAo=";
            "harmonypir-0.1.0" = "sha256-E7moHaQUhR4NUIdKsOluOGHFOkZE6bJrj26tc0f3IGQ=";
            "libdpf-0.1.0"     = "sha256-Hu4yEsxiNugk0dZe02Fz70DzOGKf9v52fhRgXtV8Vnw=";
            "onionpir-0.2.0"   = "sha256-xYbCLV7z6hwqVllH77vJWhRVl4UZL6WirLWAnfKQMHk=";
          };
        };

        # Match the build_unified_server.sh wrapper's invocation.
        # rustPlatform.buildRustPackage already adds `--profile release`
        # by default, so we omit `--release` here to avoid the
        # "argument can't be used with `--release`" conflict.
        cargoBuildFlags = [ "-p" "runtime" "--bin" "unified_server" ];

        # The repo's .cargo/config.toml declares [source."git+..."] +
        # [source.crates-io] replace-with = "vendored-sources" entries
        # for sub-task 4's offline-build path. rustPlatform.buildRustPackage
        # ALSO writes its own [source.crates-io] / git source overrides
        # into the sandbox config, which collides with ours ("Sources are
        # not allowed to be defined multiple times"). Strip the in-repo
        # source replacements during patchPhase so only the Nix-managed
        # vendor dir is visible to cargo inside the sandbox.
        postPatch = ''
          # Remove every line from the first [source.crates-io] header to
          # end of file (the source-replacement block lives at the bottom
          # of .cargo/config.toml after the AES-NI rustflags + vendor doc).
          # rustPlatform.buildRustPackage writes its own [source.*]
          # entries, and cargo errors on duplicate source definitions.
          sed -i '/^\[source\.crates-io\]/,$d' .cargo/config.toml

          # Point the onionpir C++ build's CMake at the HEXL + cpu_features
          # CMake-config packages. Since rev 7ea020a the onionpir CMakeLists
          # defaults USE_HEXL=ON on x86_64 and does `find_package(HEXL
          # CONFIG)`; HEXL's own config in turn does `find_package(
          # CpuFeatures CONFIG)`. nixpkgs' cmake hook already exports both
          # on CMAKE_PREFIX_PATH via buildInputs, but the `cmake` crate
          # (cmake-rs) spawns its own cmake — inject the prefixes into its
          # Config chain explicitly so resolution can't depend on env
          # propagation. Fully hermetic: HEXL is the Nix derivation above.
          sed -i 's|\.define("ONIONPIR_BUILD_FFI", "ON")|&\n        .define("CMAKE_PREFIX_PATH", "${hexl};${pkgs.cpu_features.dev}")|' \
              "$NIX_BUILD_TOP/cargo-vendor-dir/onionpir-0.2.0/build.rs"

          # onionpir's build.rs emits only `-l static=onionpir`. With HEXL
          # active (ONIONPIR_USE_HEXL) the engine no longer compiles in the
          # cpp/hexl_shim.cpp fallback, so libonionpir.a carries unresolved
          # intel::hexl + cpu_features symbols — a static lib does not
          # bundle its link deps. Append the transitive link directives so
          # the final unified_server link resolves (order: onionpir -> hexl
          # -> cpu_features). TODO: upstream this into onionpir's build.rs
          # (it should emit HEXL link flags whenever CMake reports HEXL
          # active) and drop this sed.
          sed -i 's|    println!("cargo:rustc-link-lib=static=onionpir");|&\n    println!("cargo:rustc-link-search=native=${hexl}/lib");\n    println!("cargo:rustc-link-lib=static=hexl");\n    println!("cargo:rustc-link-search=native=${pkgs.cpu_features}/lib");\n    println!("cargo:rustc-link-lib=dylib=cpu_features");|' \
              "$NIX_BUILD_TOP/cargo-vendor-dir/onionpir-0.2.0/build.rs"
        '';
        # Skip cargo test inside the build (live-server integration tests
        # require network + a running pir2; not appropriate for sandbox).
        doCheck = false;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          cmake
          gcc
          pkg-config
          gnumake
          # git: available to the sandbox build for any build script
          # that shells out to it. The onionpir crate is SEAL-free and
          # submodule-free, so it needs no git fetch of its own.
          git
        ];

        # Intel HEXL (Nix-built, above) + its cpu_features dependency —
        # for the onionpir C++ engine's find_package(HEXL CONFIG) /
        # find_package(CpuFeatures CONFIG) and the final link. cpu_features
        # is a shared lib, so it stays a runtime dep of unified_server in
        # the Nix closure.
        buildInputs = [ hexl pkgs.cpu_features ];

        # Strip debug info reproducibly. cargo's release default already
        # omits debug; this is defense-in-depth.
        dontStrip = false;

        # Strict sandbox (no __noChroot): the build needs no network. HEXL
        # is the Nix-built derivation above and the onionpir C++ build
        # resolves it via find_package(CONFIG) — no FetchContent; every
        # git dep is pre-fetched by Nix via cargoLock. The only gcc
        # visible is the Nix-provided one.
      };
    };

    devShells.${system}.default = pkgs.mkShell {
      packages = [
        rustToolchain
      ] ++ (with pkgs; [

        # ─── Rust / Cargo ──────────────────────────────────────────────
        # rustToolchain provides cargo + rustc + rustfmt + clippy.

        # ─── C/C++ build chain (for OnionPIR's CMake-built C++ engine) ─
        # The onionpir crate's CMakeLists sets CMAKE_POLICY_VERSION_MINIMUM,
        # so it configures cleanly under CMake 4.x — nixpkgs's `cmake`
        # (latest upstream) works as-is.
        cmake
        gnumake
        gcc
        pkg-config

        # ─── UKI build chain ──────────────────────────────────────────
        # `ukify` ships inside the systemd package on nixpkgs (no separate
        # systemd-ukify derivation). dracut handles initramfs cpio.
        dracut
        systemd       # provides ukify
        binutils      # strip, objcopy

        # ─── runit (PID 1 takeover supervisor inside Tier 3) ──────────
        # Provides runsvdir, runsv, sv, chpst — invoked by
        # /sbin/bpir-tier3-init via /etc/sv/<service>/run.
        runit

        # ─── busybox (statically linked, baked into Tier 3 initramfs) ─
        # Provides udhcpc, ip, mount, modprobe, sleep, ln, mkdir, cat, sh.
        busybox

        # ─── cloudflared (tunnel binary baked into initramfs) ─────────
        cloudflared

        # ─── Misc ─────────────────────────────────────────────────────
        coreutils  # sha256sum, find, touch, etc.
        gnused
        gawk
        git
        which
      ]);

      shellHook = ''
        echo "──────────────────────────────────────────────────────────────"
        echo "  BitcoinPIR — hermetic build env (Nix flake, sub-task 5)"
        echo "──────────────────────────────────────────────────────────────"
        echo "  rustc:       $(rustc --version 2>/dev/null || echo MISSING)"
        echo "  cargo:       $(cargo --version 2>/dev/null || echo MISSING)"
        echo "  cmake:       $(cmake --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  ukify:       $(ukify --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  dracut:      $(dracut --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  cloudflared: $(cloudflared --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  runsv:       $(which runsv 2>/dev/null || echo MISSING)"
        echo "  busybox:     $(which busybox 2>/dev/null || echo MISSING)"
        echo
        echo "  Build:"
        echo "    ./scripts/build_unified_server.sh"
        echo "    sudo ./scripts/build_uki_tier3.sh   # needs root for /boot/vmlinuz"
        echo
        echo "  This is Phase 1 of sub-task 5: pinned toolchain via dev shell."
        echo "  Phase 2 (full nix build derivation, content-addressed source"
        echo "  paths → cross-path determinism) is a follow-up — see"
        echo "  docs/PHASE3_SLICE3_REPRO_PLAN.md."
      '';
    };
  };
}
