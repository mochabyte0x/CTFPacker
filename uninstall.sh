#!/usr/bin/env bash
# =============================================================================
#  CTFPacker – Uninstaller for Debian-based systems
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
    echo -e "  Try: ${YELLOW}sudo bash uninstall.sh${NC}"
    exit 1
fi

# ── Debian/apt check ─────────────────────────────────────────────────────────
if ! command -v apt-get &>/dev/null; then
    log_error "apt-get not found. This uninstaller only supports Debian-based systems."
    exit 1
fi

# ── Resolve the real (non-root) user ─────────────────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
PIPX_BIN="$REAL_HOME/.local/bin"

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
echo -e "  ${CYAN}Uninstaller — Debian-based systems${NC}"
echo -e "  ${CYAN}Author: mocha | https://mochabyte.xyz${NC}"
echo ""

# =============================================================================
# Confirmation
# =============================================================================
echo -e "${YELLOW}${BOLD}This will remove:${NC}"
echo -e "  • CTFPacker pipx package + entry points (ctfpacker, ctfpacker-gui)"
echo -e "  • Desktop entry and icon"
echo -e "  • Shell aliases (ctfp, ctfpg) from .bashrc / .zshrc"
echo -e "  • Build artifacts (.ctfpacker/ temp dir, if present)"
echo ""
read -rp "$(echo -e "${BOLD}Continue? [y/N] ${NC}")" CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    log_warn "Aborted."
    exit 0
fi

# =============================================================================
# STEP 1 — Remove pipx package
# =============================================================================
log_banner "STEP 1 — Removing pipx package"

if sudo -u "$REAL_USER" pipx list 2>/dev/null | grep -q "ctfpacker"; then
    sudo -u "$REAL_USER" pipx uninstall ctfpacker
    log_success "ctfpacker uninstalled from pipx."
else
    log_warn "ctfpacker not found in pipx — skipping."
fi

# =============================================================================
# STEP 2 — Remove desktop entry and icon
# =============================================================================
log_banner "STEP 2 — Removing desktop entry and icon"

DESKTOP_PATH="$REAL_HOME/.local/share/applications/ctfpacker-gui.desktop"
ICON_PATH="$REAL_HOME/.local/share/icons/ctfpacker.png"

if [[ -f "$DESKTOP_PATH" ]]; then
    rm -f "$DESKTOP_PATH"
    log_success "Desktop entry removed."
else
    log_warn "Desktop entry not found — skipping."
fi

if [[ -f "$ICON_PATH" ]]; then
    rm -f "$ICON_PATH"
    log_success "Icon removed."
else
    log_warn "Icon not found — skipping."
fi

# Refresh desktop database
if command -v update-desktop-database &>/dev/null; then
    sudo -u "$REAL_USER" update-desktop-database "$REAL_HOME/.local/share/applications" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "$REAL_HOME/.local/share/icons" 2>/dev/null || true
fi

# =============================================================================
# STEP 3 — Remove shell aliases
# =============================================================================
log_banner "STEP 3 — Removing shell aliases"

remove_aliases() {
    local rc_file="$1"
    if [[ -f "$rc_file" ]] && grep -q 'CTFPacker aliases' "$rc_file" 2>/dev/null; then
        # Remove the alias block (comment header + 2 alias lines + footer comment)
        sed -i '/# ── CTFPacker aliases/,/# ──────────────────────────────────────────────────────────────────────────────/d' "$rc_file"
        # Also strip any leftover blank line that sed may leave
        sed -i '/^$/N;/^\n$/d' "$rc_file"
        log_success "Aliases removed from $rc_file"
    else
        log_warn "No CTFPacker aliases found in ${rc_file} — skipping."
    fi
}

remove_aliases "$REAL_HOME/.bashrc"
remove_aliases "$REAL_HOME/.zshrc"

# =============================================================================
# STEP 4 — Remove build artifacts
# =============================================================================
log_banner "STEP 4 — Removing build artifacts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTFPACKER_TMP="$SCRIPT_DIR/Linux/.ctfpacker"

if [[ -d "$CTFPACKER_TMP" ]]; then
    rm -rf "$CTFPACKER_TMP"
    log_success "Build temp dir removed: $CTFPACKER_TMP"
else
    log_warn "No build temp dir found — skipping."
fi

# =============================================================================
# STEP 5 — APT packages (optional)
# =============================================================================
log_banner "STEP 5 — APT packages (optional)"

APT_PKGS=(
    clang
    lld
    nasm
    mingw-w64
    osslsigncode
    pipx
)

echo -e "${YELLOW}${BOLD}The following APT packages were installed by CTFPacker:${NC}"
printf '  %s\n' "${APT_PKGS[@]}"
echo ""
echo -e "${YELLOW}  WARNING: These may be used by other tools on your system.${NC}"
echo ""
read -rp "$(echo -e "${BOLD}Remove these APT packages? [y/N] ${NC}")" REMOVE_APT

if [[ "$REMOVE_APT" =~ ^[Yy]$ ]]; then
    log_info "Removing APT packages..."
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "${APT_PKGS[@]}" 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    log_success "APT packages removed."
else
    log_warn "APT packages kept."
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Uninstall complete!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}The CTFPacker source directory was NOT removed.${NC}"
echo -e "  To fully delete it: ${YELLOW}rm -rf $SCRIPT_DIR${NC}"
echo ""
echo -e "  ${CYAN}Reload your shell to clear the aliases:${NC}"
echo -e "    ${YELLOW}source ~/.bashrc${NC}  or open a new terminal"
echo ""
