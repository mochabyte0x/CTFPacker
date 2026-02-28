#!/usr/bin/env bash
# =============================================================================
#  CTFPacker – Automated Installer for Debian-based systems
#  Tested on: Kali Linux, Ubuntu 22.04+, Debian 12+
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}[*]${NC} $*"; }
log_success() { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*" >&2; }
log_banner()  { echo -e "\n${BOLD}${CYAN}$*${NC}\n"; }

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root."
    echo -e "  Try: ${YELLOW}sudo bash install.sh${NC}"
    exit 1
fi

# ── Debian/apt check ─────────────────────────────────────────────────────────
if ! command -v apt-get &>/dev/null; then
    log_error "apt-get not found."
    log_error "This installer only supports Debian-based systems (Kali Linux, Ubuntu, Debian)."
    exit 1
fi

# ── Resolve the real (non-root) user that invoked sudo ───────────────────────
# pipx must be run as the actual user, not root, so binaries land in
# ~/.local/bin of the invoking user rather than /root/.local/bin.
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
PIPX_BIN="$REAL_HOME/.local/bin"

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_DIR="$SCRIPT_DIR/Linux"

if [[ ! -d "$LINUX_DIR" ]]; then
    log_error "Linux/ directory not found. Make sure you run this from the CTFPacker root."
    exit 1
fi

# ── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}"
cat << 'EOF'

 ▄████▄  ▄▄▄█████▓  █████▒██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███  
▒██▀ ▀█  ▓  ██▒ ▓▒▓██   ▒▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒ ▓██░ ▒░▒████ ░▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█▒  ░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░  ▒██▒ ░ ░▒█░   ▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░  ▒ ░░    ▒ ░   ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒       ░     ░     ░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
░          ░       ░ ░   ░░         ░   ▒   ░        ░ ░░ ░    ░     ░░   ░ 
░ ░                                     ░  ░░ ░      ░  ░      ░  ░   ░     
░                                           ░                               

EOF
echo -e "${NC}"
echo -e "  ${CYAN}Automated Installer — Debian-based systems${NC}"
echo -e "  ${CYAN}Author: mocha | https://mochabyte.xyz${NC}"
echo ""

# =============================================================================
# STEP 1 — APT packages
# =============================================================================
log_banner "STEP 1/3 — Installing APT dependencies"

APT_PKGS=(
    clang           # Clang compiler (cross-compilation)
    lld             # LLVM linker (used with -fuse-ld=lld)
    make            # GNU Make
    nasm            # Netwide Assembler (for SysWhispers asm)
    mingw-w64       # MinGW-w64 cross-compilation toolchain
    python3         # Python 3 interpreter
    pipx            # Isolated Python app installer
    osslsigncode    # PE code signing (optional, needed for -pfx)
)

log_info "Updating package lists..."
apt-get update -qq

log_info "Installing: ${APT_PKGS[*]}"
DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PKGS[@]}"

log_success "APT packages installed."

# =============================================================================
# STEP 2 — pipx install
# =============================================================================
log_banner "STEP 2/3 — Installing CTFPacker via pipx"

# Ensure pipx's bin dir is on PATH for this session
export PATH="$PIPX_BIN:$PATH"

# pipx ensurepath writes to the real user's shell rc files
log_info "Running pipx ensurepath for user '$REAL_USER' ..."
sudo -u "$REAL_USER" pipx ensurepath --force

# If a previous install exists, reinstall cleanly
if sudo -u "$REAL_USER" pipx list 2>/dev/null | grep -q "ctfpacker"; then
    log_warn "Existing ctfpacker pipx install found — reinstalling."
    sudo -u "$REAL_USER" pipx uninstall ctfpacker
fi

log_info "Installing CTFPacker package (from $LINUX_DIR) ..."
sudo -u "$REAL_USER" pipx install "$LINUX_DIR"

log_success "CTFPacker installed via pipx."
log_info  "Binaries are available at: $PIPX_BIN"

# =============================================================================
# STEP 2b — Desktop entry (.desktop file + icon)
# =============================================================================
log_banner "STEP 2b/3 — Installing desktop application entry"

ICON_DIR="$REAL_HOME/.local/share/icons"
APPS_DIR="$REAL_HOME/.local/share/applications"
DESKTOP_PATH="$APPS_DIR/ctfpacker-gui.desktop"

mkdir -p "$ICON_DIR" "$APPS_DIR"

# ── PNG icon (bundled Logo.png from assets/) ──────────────────────────────────
LOGO_SRC="$SCRIPT_DIR/assets/Logo.png"
ICON_PATH="$ICON_DIR/ctfpacker.png"

if [[ -f "$LOGO_SRC" ]]; then
    cp "$LOGO_SRC" "$ICON_PATH"
    chown "$REAL_USER":"$(id -gn "$REAL_USER")" "$ICON_PATH"
    chmod 644 "$ICON_PATH"
    log_success "Icon installed → $ICON_PATH"
else
    log_warn "assets/Logo.png not found — desktop icon will be missing."
    ICON_PATH="ctfpacker"   # fall back to XDG theme lookup
fi

# ── .desktop file ─────────────────────────────────────────────────────────────
cat > "$DESKTOP_PATH" << DESKTOPEOF
[Desktop Entry]
Version=1.0
Type=Application
Name=CTFPacker GUI
GenericName=Shellcode Packer
Comment=AV-evading Windows shellcode loader for CTFs and pentest exams
Exec=$PIPX_BIN/ctfpacker-gui
Icon=$ICON_PATH
Terminal=false
Categories=Security;Development;
Keywords=ctf;pentest;shellcode;packer;redteam;av;evasion;
StartupWMClass=CTFPacker
StartupNotify=true
DESKTOPEOF

chown "$REAL_USER":"$(id -gn "$REAL_USER")" "$DESKTOP_PATH"
chmod 644 "$DESKTOP_PATH"
log_success "Desktop entry installed → $DESKTOP_PATH"

# Refresh the desktop database so the launcher picks it up immediately
if command -v update-desktop-database &>/dev/null; then
    sudo -u "$REAL_USER" update-desktop-database "$APPS_DIR" 2>/dev/null || true
    log_success "Desktop database updated."
fi

# GTK icon cache refresh (GNOME / XFCE)
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "$ICON_DIR" 2>/dev/null || true
fi

# =============================================================================
# STEP 2c — Shell aliases  (ctfp / ctfpg)
# =============================================================================
ALIAS_BLOCK='
# ── CTFPacker aliases ────────────────────────────────────────────────────────
alias ctfp="ctfpacker"
alias ctfpg="ctfpacker-gui"
# ────────────────────────────────────────────────────────────────────────────'

install_aliases() {
    local rc_file="$1"
    if [[ -f "$rc_file" ]]; then
        if grep -q 'CTFPacker aliases' "$rc_file" 2>/dev/null; then
            log_warn "Aliases already present in $rc_file — skipping."
        else
            echo "$ALIAS_BLOCK" >> "$rc_file"
            log_success "Aliases added to $rc_file"
        fi
    fi
}

BASHRC="$REAL_HOME/.bashrc"
ZSHRC="$REAL_HOME/.zshrc"

install_aliases "$BASHRC"
install_aliases "$ZSHRC"

# Apply immediately to the current (root) session so the verify step can see them
# shellcheck disable=SC1090
eval "alias ctfp='ctfpacker'; alias ctfpg='ctfpacker-gui'"

# =============================================================================
# STEP 3 — Verify toolchain
# =============================================================================
log_banner "STEP 3/3 — Verifying toolchain"

MISSING=()

check_tool() {
    local tool="$1"
    local display="${2:-$1}"
    if command -v "$tool" &>/dev/null; then
        log_success "${display} → $(command -v "$tool")"
    else
        log_warn "${display} → NOT FOUND in PATH"
        MISSING+=("$tool")
    fi
}

check_tool "clang"                    "clang"
check_tool "lld"                      "lld"
check_tool "nasm"                     "nasm"
check_tool "make"                     "make"
check_tool "x86_64-w64-mingw32-gcc"  "mingw-w64 (x86_64)"
check_tool "osslsigncode"             "osslsigncode"
check_tool "pipx"                     "pipx"

# Check ctfpacker entry point (may not be in root's PATH yet — check by full path)
if [[ -f "$PIPX_BIN/ctfpacker" ]]; then
    log_success "ctfpacker     → $PIPX_BIN/ctfpacker"
else
    log_warn "ctfpacker entry point not found in $PIPX_BIN"
    MISSING+=("ctfpacker")
fi

# Verify MinGW sysroot paths used by Makefile
TARGET_TRIPLE="x86_64-w64-mingw32"
MINGW_INCLUDE="/usr/${TARGET_TRIPLE}/include"
MINGW_LIB="/usr/${TARGET_TRIPLE}/lib"
GCC_WIN32_PATH="$(find /usr/lib/gcc/${TARGET_TRIPLE}/ -type d -name "*win32" 2>/dev/null | head -n1 || true)"

if [[ -d "$MINGW_INCLUDE" ]]; then
    log_success "MinGW includes → $MINGW_INCLUDE"
else
    log_warn "MinGW includes not found at $MINGW_INCLUDE"
    MISSING+=("mingw-include")
fi

if [[ -d "$MINGW_LIB" ]]; then
    log_success "MinGW libs      → $MINGW_LIB"
else
    log_warn "MinGW libs not found at $MINGW_LIB"
    MISSING+=("mingw-lib")
fi

if [[ -n "$GCC_WIN32_PATH" ]]; then
    log_success "GCC win32 path  → $GCC_WIN32_PATH"
else
    log_warn "GCC win32 runtime path not found (will fall back to MINGW_LIB in Makefile)"
fi

# Check for winhttp / ntdll import stubs (needed at link time)
for stub in libwinhttp.a libntdll.a; do
    if [[ -f "$MINGW_LIB/$stub" ]]; then
        log_success "$stub found"
    else
        log_warn "$stub not found in $MINGW_LIB — linking may fail"
    fi
done

# =============================================================================
# Summary
# =============================================================================
echo ""
if [[ ${#MISSING[@]} -gt 0 ]]; then
    log_warn "Some components were not found: ${MISSING[*]}"
    log_warn "If these are PATH-related, open a new shell or run:"
    log_warn "  source ~/.bashrc  (or ~/.zshrc)"
else
    log_success "All components verified successfully."
fi

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Installation complete!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}CTFPacker is installed globally for user '${REAL_USER}'.${NC}"
echo -e "  ${CYAN}Open a new terminal (or source your shell rc) then:${NC}"
echo ""
echo -e "  ${CYAN}App launcher:${NC}"
echo -e "    Search for ${YELLOW}CTFPacker GUI${NC} in your application menu / launcher"
echo ""
echo -e "  ${CYAN}Run CTFPacker (CLI):${NC}"
echo -e "    ${YELLOW}ctfpacker -h${NC}   ${CYAN}or${NC}   ${YELLOW}ctfp -h${NC}"
echo ""
echo -e "  ${CYAN}Run CTFPacker (GUI):${NC}"
echo -e "    ${YELLOW}ctfpacker-gui${NC}   ${CYAN}or${NC}   ${YELLOW}ctfpg${NC}"
echo ""
echo -e "  ${CYAN}Staged example:${NC}"
echo -e "    ${YELLOW}ctfp staged -p shellcode.bin -i 192.168.1.1 -po 8080 -pa /shell.bin -e -s${NC}"
echo ""
echo -e "  ${CYAN}Stageless example:${NC}"
echo -e "    ${YELLOW}ctfp stageless -p shellcode.bin -e -s${NC}"
echo ""
echo -e "  ${CYAN}Aliases installed:${NC}  ${YELLOW}ctfp${NC} → ctfpacker    ${YELLOW}ctfpg${NC} → ctfpacker-gui"
echo -e "  ${CYAN}(Reload your shell:${NC}  ${YELLOW}source ~/.bashrc${NC}  or open a new terminal)"
echo ""
