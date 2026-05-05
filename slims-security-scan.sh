#!/bin/bash
# ============================================================
# SLIMS Security Scanner
# Tujuan: Mendeteksi file mencurigakan (judi online, shell backdoor, malware)
# Penggunaan: sudo bash slims_security_scan.sh /path/ke/slims
# ============================================================

TARGET_DIR="${1:-/var/www/html}"
REPORT_FILE="security_report_$(date +%Y%m%d_%H%M%S).txt"
RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

echo "============================================================" | tee "$REPORT_FILE"
echo " SLIMS Security Scanner - $(date)" | tee -a "$REPORT_FILE"
echo " Target: $TARGET_DIR" | tee -a "$REPORT_FILE"
echo "============================================================" | tee -a "$REPORT_FILE"

# ------------------------------------------------------------
# 1. DETEKSI KONTEN JUDI ONLINE
# ------------------------------------------------------------
echo -e "\n${YLW}[1] Scanning konten judi online...${NC}" | tee -a "$REPORT_FILE"

JUDI_KEYWORDS=(
    "slot" "togel" "poker" "casino" "betting" "sbobet" "maxbet"
    "pragmatic" "pg.soft" "habanero" "joker123" "nexus.slot"
    "gacor" "jackpot" "taruhan" "bandar.bola" "agen.slot"
    "rtp.live" "scatter" "demo.slot" "situs.judi"
)

for kw in "${JUDI_KEYWORDS[@]}"; do
    results=$(grep -rli "$kw" "$TARGET_DIR" \
        --include="*.php" --include="*.html" --include="*.htm" \
        --include="*.js" --include="*.txt" 2>/dev/null)
    if [ -n "$results" ]; then
        echo -e "${RED}  [JUDI] Keyword '$kw' ditemukan di:${NC}" | tee -a "$REPORT_FILE"
        echo "$results" | while read f; do echo "    - $f"; done | tee -a "$REPORT_FILE"
    fi
done

# ------------------------------------------------------------
# 2. DETEKSI PHP SHELL / BACKDOOR
# ------------------------------------------------------------
echo -e "\n${YLW}[2] Scanning PHP shell & backdoor...${NC}" | tee -a "$REPORT_FILE"

# Pola berbahaya yang umum di shell backdoor
SHELL_PATTERNS=(
    "eval(base64_decode"
    "eval(gzinflate"
    "eval(str_rot13"
    "eval(gzuncompress"
    "assert(\$_"
    "preg_replace.*\/e"
    "system(\$_"
    "exec(\$_"
    "passthru(\$_"
    "shell_exec(\$_"
    "base64_decode.*eval"
    "str_replace.*chr("
    "\$_POST\[.*\](\s*)\("
    "\$_GET\[.*\](\s*)\("
    "\$_COOKIE\[.*\](\s*)\("
    "\$_REQUEST\[.*\](\s*)\("
    "FilesMan"
    "WSO Shell"
    "r57shell"
    "c99shell"
    "b374k"
    "phpspy"
    "Safe0ver"
    "webshell"
    "<?php.*eval.*base64"
)

for pattern in "${SHELL_PATTERNS[@]}"; do
    results=$(grep -rli -P "$pattern" "$TARGET_DIR" \
        --include="*.php" --include="*.phtml" --include="*.php5" \
        --include="*.php7" --include="*.phar" 2>/dev/null)
    if [ -n "$results" ]; then
        echo -e "${RED}  [SHELL] Pattern '$pattern' ditemukan:${NC}" | tee -a "$REPORT_FILE"
        echo "$results" | while read f; do echo "    - $f"; done | tee -a "$REPORT_FILE"
    fi
done

# ------------------------------------------------------------
# 3. FILE PHP TERSEMBUNYI DI FOLDER UPLOAD / NON-PHP
# ------------------------------------------------------------
echo -e "\n${YLW}[3] Mencari file PHP di folder upload/images...${NC}" | tee -a "$REPORT_FILE"

UPLOAD_DIRS=("upload" "uploads" "images" "img" "files" "cache" "temp" "tmp" "backup")

for dir in "${UPLOAD_DIRS[@]}"; do
    found=$(find "$TARGET_DIR" -type d -iname "$dir" 2>/dev/null)
    if [ -n "$found" ]; then
        php_in_upload=$(find "$found" -name "*.php" -o -name "*.phtml" -o -name "*.php5" 2>/dev/null)
        if [ -n "$php_in_upload" ]; then
            echo -e "${RED}  [SUSPECT] File PHP di folder '$dir':${NC}" | tee -a "$REPORT_FILE"
            echo "$php_in_upload" | while read f; do echo "    - $f"; done | tee -a "$REPORT_FILE"
        fi
    fi
done

# ------------------------------------------------------------
# 4. FILE DENGAN EKSTENSI GANDA (double extension)
# ------------------------------------------------------------
echo -e "\n${YLW}[4] Mencari file ekstensi ganda...${NC}" | tee -a "$REPORT_FILE"

find "$TARGET_DIR" -type f \( \
    -name "*.php.jpg" -o -name "*.php.png" -o -name "*.php.gif" \
    -o -name "*.php.txt" -o -name "*.php.pdf" -o -name "*.jpg.php" \
    -o -name "*.png.php" \) 2>/dev/null | while read f; do
    echo -e "${RED}  [DOUBLE EXT] $f${NC}" | tee -a "$REPORT_FILE"
done

# ------------------------------------------------------------
# 5. FILE YANG BARU DIMODIFIKASI (< 7 hari)
# ------------------------------------------------------------
echo -e "\n${YLW}[5] File PHP yang dimodifikasi dalam 7 hari terakhir...${NC}" | tee -a "$REPORT_FILE"

find "$TARGET_DIR" -type f -name "*.php" -mtime -7 2>/dev/null | while read f; do
    mod_time=$(stat -c "%y" "$f" 2>/dev/null | cut -d'.' -f1)
    echo "  [RECENT] $f  (diubah: $mod_time)" | tee -a "$REPORT_FILE"
done

# ------------------------------------------------------------
# 6. FILE DENGAN PERMISSION MENCURIGAKAN (777)
# ------------------------------------------------------------
echo -e "\n${YLW}[6] File dengan permission 777...${NC}" | tee -a "$REPORT_FILE"

find "$TARGET_DIR" -type f -perm 0777 2>/dev/null | while read f; do
    echo -e "${RED}  [PERM 777] $f${NC}" | tee -a "$REPORT_FILE"
done

# ------------------------------------------------------------
# 7. IFRAME & REDIRECT MENCURIGAKAN
# ------------------------------------------------------------
echo -e "\n${YLW}[7] Mencari iframe & redirect mencurigakan...${NC}" | tee -a "$REPORT_FILE"

MALWARE_PATTERNS=(
    "<iframe.*src=.*http"
    "document.write.*unescape"
    "window.location.*=.*http"
    "header.*Location.*http"
    "base64_decode.*http"
    "curl_exec.*\$_"
)

for pattern in "${MALWARE_PATTERNS[@]}"; do
    results=$(grep -rli -P "$pattern" "$TARGET_DIR" \
        --include="*.php" --include="*.html" --include="*.js" 2>/dev/null)
    if [ -n "$results" ]; then
        echo -e "${RED}  [MALWARE] Pattern '$pattern':${NC}" | tee -a "$REPORT_FILE"
        echo "$results" | while read f; do echo "    - $f"; done | tee -a "$REPORT_FILE"
    fi
done

# ------------------------------------------------------------
# 8. DETEKSI CRYPTO MINER
# ------------------------------------------------------------
echo -e "\n${YLW}[8] Mencari crypto miner...${NC}" | tee -a "$REPORT_FILE"

MINER_PATTERNS=(
    "coinhive" "cryptonight" "minero" "stratum+tcp"
    "CoinHive.Anonymous" "miner.start" "wasm.min.js"
    "cryptoloot" "coin-hive"
)

for kw in "${MINER_PATTERNS[@]}"; do
    results=$(grep -rli "$kw" "$TARGET_DIR" 2>/dev/null)
    if [ -n "$results" ]; then
        echo -e "${RED}  [MINER] Keyword '$kw':${NC}" | tee -a "$REPORT_FILE"
        echo "$results" | while read f; do echo "    - $f"; done | tee -a "$REPORT_FILE"
    fi
done

# ------------------------------------------------------------
# RINGKASAN
# ------------------------------------------------------------
echo -e "\n============================================================" | tee -a "$REPORT_FILE"
echo -e "${GRN} Scan selesai. Report disimpan di: $REPORT_FILE${NC}" | tee -a "$REPORT_FILE"
echo "============================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "LANGKAH SELANJUTNYA:" | tee -a "$REPORT_FILE"
echo "  1. Review setiap file yang ditemukan secara manual" | tee -a "$REPORT_FILE"
echo "  2. Backup dulu sebelum menghapus file apapun" | tee -a "$REPORT_FILE"
echo "  3. Untuk file judi: hapus dan periksa bagaimana bisa masuk" | tee -a "$REPORT_FILE"
echo "  4. Untuk shell backdoor: hapus, ganti password DB & CMS" | tee -a "$REPORT_FILE"
echo "  5. Update SLIMS ke versi terbaru setelah pembersihan" | tee -a "$REPORT_FILE"
echo "============================================================" | tee -a "$REPORT_FILE"
