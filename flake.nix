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

    # OnionPIR (the `onionpir` git dep) builds a C++ engine through its
    # crate-local CMake project. That engine has an optional Intel-HEXL
    # fast path (x86_64 NTT) plus an in-crate scalar fallback shim. The
    # Nix build forces the scalar shim: postPatch (below) injects
    # `-DUSE_HEXL=OFF` into the vendored onionpir build.rs. That keeps the
    # build fully hermetic — no HEXL fetch, no cpu_features, no CMake
    # FetchContent network access — at the cost of x86 NTT speed. (The
    # OnionPIRv2-fork has been SEAL-free since its BV-keyswitch rewrite,
    # so there is also no SEAL submodule to vendor.)

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
      # Phase 2 extension: produce the Tier 3 UKI inside Nix's sandbox.
      # Replaces dracut entirely with NixOS's `makeInitrdNG` (which
      # natively handles /nix/store paths — copies whole derivations
      # into the initramfs at their store path, sets up symlinks at
      # target paths). The bpir-* dracut modules' install() functions
      # are translated into a `contents` list below.
      #
      # The kernel image baked here is Nix's, NOT the Ubuntu kernel
      # production runs. Different kernel → different UKI sha →
      # different MEASUREMENT. A v5+ production deploy via this flake
      # would update web/src/attest-pin.ts after re-deriving the
      # MEASUREMENT.
      #
      # WIP CAVEATS — initial spike. Things still needing attention to
      # produce a fully bootable Tier 3 v5 UKI:
      #   - bpir-tier3-init.sh hardcodes /usr/bin/runsvdir, /sbin/udhcpc,
      #     etc. With Nix paths these don't exist. Either patch the script
      #     in the contents list or set up symlinks via PATH-bind.
      #   - Kernel modules: makeInitrdNG doesn't auto-include /lib/modules.
      #     For SEV-SNP guest we need virtio_*, ccp, sev-guest, tsm_report
      #     — production currently expects to modprobe these. Either
      #     ensure they're built INTO the kernel (=y instead of =m) or
      #     bundle the modules tree into contents.
      #   - tunnel.env loaded at runtime from rootfs (per sub-task 3b),
      #     no change needed here.
      tier3-uki = let
        kernel = pkgs.linuxPackages_6_12.kernel;
        unifiedServer = self.packages.${system}.unified-server;

        # Scripts from scripts/dracut/97bpir-tier3-init/, copied verbatim
        # into the initramfs at the paths the boot flow expects.
        bpirInitScript      = ./scripts/dracut/97bpir-tier3-init/bpir-tier3-init.sh;
        cloudflaredRun      = ./scripts/dracut/97bpir-tier3-init/cloudflared-run.sh;
        unifiedServerRun    = ./scripts/dracut/97bpir-tier3-init/unified-server-run.sh;
        udhcpcDefaultScript = ./scripts/dracut/97bpir-tier3-init/udhcpc-default.script;

        initrd = pkgs.makeInitrdNG {
          name = "bpir-tier3-initrd";
          # Each `source` is copied into the initramfs at its /nix/store
          # path. Where target is given, a symlink at that path resolves
          # back to the in-initramfs Nix-store path. Closures (library
          # deps) get pulled in automatically by makeInitrdNG's reference
          # walk.
          contents = [
            # Binaries (whole derivations → all of /bin is reachable)
            { source = pkgs.cloudflared;  target = "/bin/cloudflared"; }
            { source = unifiedServer;     target = "/bin/unified_server"; }
            { source = pkgs.runit;        target = "/bin/runit"; }
            { source = pkgs.busybox;      target = "/bin/busybox"; }
            { source = pkgs.iproute2;     target = "/bin/ip"; }
            { source = pkgs.kmod;         target = "/bin/modprobe"; }
            { source = pkgs.util-linux;   target = "/bin/mount"; }

            # Static scripts (no symlink needed — placed at target directly)
            { source = bpirInitScript;      target = "/sbin/bpir-tier3-init"; }
            { source = cloudflaredRun;      target = "/etc/sv/cloudflared/run"; }
            { source = unifiedServerRun;    target = "/etc/sv/unified_server/run"; }
            { source = udhcpcDefaultScript; target = "/etc/udhcpc/default.script"; }
          ];
        };

      in pkgs.runCommand "bpir-tier3-uki" {
        # ukify isn't reliably available in nixpkgs (`systemdUkify`
        # build is broken on current nixos-unstable). Bypass ukify and
        # use objcopy directly — that's all ukify does fundamentally
        # (assemble PE/EFI sections via the linuxx64.efi.stub, which IS
        # in pkgs.systemd at /lib/systemd/boot/efi/).
        nativeBuildInputs = with pkgs; [ binutils ];
        passthru = { inherit initrd kernel; };
      } ''
        mkdir -p $out
        STUB=${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub
        [ -f "$STUB" ] || { echo "ERROR: $STUB not found"; exit 1; }

        # Write cmdline + os-release as small section payloads.
        printf '%s' \
            "rdinit=/sbin/bpir-tier3-init console=ttyS0,115200 console=tty1 loglevel=7" \
            > cmdline
        printf 'NAME="bpir"\nVERSION_ID="tier3-v5-nix"\n' > os-release

        # objcopy adds PE sections to the stub. VMAs must be page-
        # aligned (4 KiB) and non-overlapping. Addresses below are the
        # canonical layout systemd's ukify uses (sufficient gaps for
        # multi-MiB initrd payloads).
        objcopy \
            --add-section .osrel=os-release    --change-section-vma .osrel=0x20000 \
            --add-section .cmdline=cmdline     --change-section-vma .cmdline=0x30000 \
            --add-section .linux=${kernel}/bzImage \
            --change-section-vma .linux=0x2000000 \
            --add-section .initrd=${initrd}/initrd \
            --change-section-vma .initrd=0x3000000 \
            $STUB \
            $out/bpir-tier3.efi

        sha256sum $out/bpir-tier3.efi | tee $out/bpir-tier3.efi.sha256
        echo
        echo "kernel: ${kernel}/bzImage"
        echo "initrd: ${initrd}/initrd"
        echo "binary inside initrd: ${unifiedServer}/bin/unified_server"
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
          # 2026-05-19 re-pin: onionpir aa7710d → c7ed905 — the
          # OnionPIRv2-fork "self-contained crate" restructure moved the
          # CMake project + cpp/ engine inside rust/onionpir/. New rev →
          # new content hash (refreshed below via the fake-hash cycle).
          outputHashes = {
            "arc-0.1.0"        = "sha256-tUyvnyJoNTlrXpudIZ3Er6Mqj8zmltBtY06kF9P6hp0=";
            "fastprp-0.1.0"    = "sha256-GVTeA1yBdpOj0GHcKTqQZz+1+AvV+tBkvUewTnNSlAo=";
            "harmonypir-0.1.0" = "sha256-E7moHaQUhR4NUIdKsOluOGHFOkZE6bJrj26tc0f3IGQ=";
            "libdpf-0.1.0"     = "sha256-Hu4yEsxiNugk0dZe02Fz70DzOGKf9v52fhRgXtV8Vnw=";
            "onionpir-0.2.0"   = "sha256-MbCbG1rmT/ORYyBHzfOuqdChDhUMq/f41ht3hktCGVQ=";
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

          # Build OnionPIR's C++ engine with the in-crate scalar shim
          # instead of Intel HEXL. The onionpir crate's CMakeLists
          # defaults USE_HEXL=ON on x86_64, then resolves HEXL through a
          # hardcoded HEXL_DIR (an upstream author's absolute path) that
          # does not exist in the sandbox — find_package(HEXL REQUIRED)
          # would FATAL_ERROR. USE_HEXL=OFF selects cpp/hexl_compat/ +
          # cpp/hexl_shim.cpp, bundled inside the crate, so the build
          # needs no external HEXL. Inject the define into the vendored
          # build.rs's cmake::Config chain.
          sed -i 's|\.define("ONIONPIR_BUILD_FFI", "ON")|&\n        .define("USE_HEXL", "OFF")|' \
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

        # No extra buildInputs: the onionpir C++ engine links only the
        # C++ runtime (libstdc++, from gcc) — no HEXL, no SEAL, no OpenMP.
        buildInputs = [ ];

        # Strip debug info reproducibly. cargo's release default already
        # omits debug; this is defense-in-depth.
        dontStrip = false;

        # Strict sandbox (no __noChroot): the build needs no network.
        # USE_HEXL=OFF removes the only step that ever wanted it (HEXL's
        # CMake FetchContent); every git dep is pre-fetched by Nix via
        # cargoLock. The only gcc visible is the Nix-provided one.
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
