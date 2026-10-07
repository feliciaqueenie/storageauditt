/**
 * storageauditt.js
 * Utilitas Command-Line (CLI Tool) Audit Penyimpanan Mandiri (Zero-Dependency)
 * Menggunakan modul bawaan Node.js: fs, path, crypto, readline
 * 
 * Kebutuhan yang diimplementasikan:
 * - STG-01: Recursive Scan (Semua subfolder, metadata: nama, path, bytes, SHA-256)
 * - STG-02: Duplicate Detection (Pengelompokan SHA-256 identik)
 * - STG-03: Giant File Flagging (File > 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (Ringkasan metrik & daftar file rapi)
 * - STG-05: Safe Cleanup Confirmation (Konfirmasi interaktif Y/N, pertahankan 1 file asli)
 * - STG-06: Zero-Dependency Portability (Hanya runtime Node.js native)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Ambang batas Giant File: 2 MB = 2 * 1024 * 1024 bytes (2.048 KB)
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024;

// File skrip audit yang diabaikan agar tidak mempengaruhi hasil audit
const AUDIT_SCRIPT_FILES = new Set([
  'storageauditt.js',
  'storage_audit.js',
  'storageauditt.py',
  'storage_audit.py'
]);

/**
 * Format bytes ke representasi terbaca (Bytes, KB, MB, GB)
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Hitung hash SHA-256 dari sebuah file
 */
function calculateSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

/**
 * STG-01: Recursive Scan
 * Memindai target directory dan seluruh subfolder secara mendalam
 */
async function scanDirectory(dirPath, fileList = []) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      await scanDirectory(fullPath, fileList);
    } else if (entry.isFile()) {
      // Lewati file skrip audit itu sendiri
      if (AUDIT_SCRIPT_FILES.has(entry.name.toLowerCase())) {
        continue;
      }
      try {
        const stats = fs.statSync(fullPath);
        const hash = await calculateSha256(fullPath);
        fileList.push({
          name: entry.name,
          fullPath: fullPath,
          relativePath: path.relative(process.cwd(), fullPath),
          sizeBytes: stats.size,
          hash: hash,
          mtime: stats.mtime
        });
      } catch (err) {
        console.error(`Gagal membaca file: ${fullPath} (${err.message})`);
      }
    }
  }

  return fileList;
}

/**
 * Nilai heuristik untuk menentukan mana file asli (original) vs salinan (copy)
 * Skor lebih rendah = lebih diprioritaskan sebagai file asli
 */
function getOriginalScore(fileName) {
  let score = 0;
  const lower = fileName.toLowerCase();

  if (lower.includes(' - copy')) score += 10;
  if (lower.includes(' - salinan')) score += 10;
  if (lower.includes(' (1)') || lower.includes(' (2)') || lower.includes(' (3)')) score += 10;
  if (lower.includes('_copy')) score += 8;
  if (lower.includes('_backup')) score += 7;
  if (lower.includes('_v2') || lower.includes('_v3')) score += 6;
  if (lower.includes('_edit2') || lower.includes('_edit')) score += 5;
  if (lower.includes('_final')) score += 4;
  if (lower.includes('_fix')) score += 3;
  if (lower.endsWith('.tmp')) score += 20;

  // Nama lebih pendek biasanya nama asli
  score += fileName.length * 0.05;
  return score;
}

/**
 * STG-02: Duplicate Detection
 */
function detectDuplicates(files) {
  const hashMap = new Map();

  for (const file of files) {
    if (!hashMap.has(file.hash)) {
      hashMap.set(file.hash, []);
    }
    hashMap.get(file.hash).push(file);
  }

  const duplicateGroups = [];
  for (const [hash, group] of hashMap.entries()) {
    if (group.length > 1) {
      // Urutkan anggota grup: file asli teratas (skor terendah)
      group.sort((a, b) => getOriginalScore(a.name) - getOriginalScore(b.name));
      duplicateGroups.push({
        hash,
        sizeBytes: group[0].sizeBytes,
        original: group[0],
        duplicates: group.slice(1),
        allFiles: group
      });
    }
  }

  return duplicateGroups;
}

/**
 * STG-03: Giant File Flagging (Ukuran >= 2 MB / 2.048 KB)
 */
function detectGiantFiles(files) {
  return files
    .filter(file => file.sizeBytes >= GIANT_FILE_THRESHOLD_BYTES)
    .sort((a, b) => b.sizeBytes - a.sizeBytes);
}

/**
 * STG-04: Terminal Report
 */
function printReport(targetDir, files, duplicateGroups, giantFiles, tmpFiles) {
  const totalSizeBytes = files.reduce((acc, f) => acc + f.sizeBytes, 0);
  const wastedBytes = duplicateGroups.reduce((acc, grp) => {
    return acc + (grp.sizeBytes * grp.duplicates.length);
  }, 0);
  const totalDuplicateCopies = duplicateGroups.reduce((acc, grp) => acc + grp.duplicates.length, 0);

  const divider = '='.repeat(70);
  const subDivider = '-'.repeat(70);

  console.log('\n' + divider);
  console.log('       LAPORAN AUDIT PENYIMPANAN SISTEM (STORAGE AUDIT REPORT)');
  console.log(divider);
  console.log(` Direktori Target         : ${path.resolve(targetDir)}`);
  console.log(` Total File Terpindai     : ${files.length} file`);
  console.log(` Total Kapasitas Folder   : ${formatBytes(totalSizeBytes)} (${totalSizeBytes.toLocaleString()} bytes)`);
  console.log(` Kelompok Duplikat        : ${duplicateGroups.length} kelompok (${totalDuplicateCopies} file salinan)`);
  console.log(` File Raksasa (>= 2 MB)   : ${giantFiles.length} file`);
  console.log(` Sampah File .tmp         : ${tmpFiles.length} file`);
  console.log(` Potensi Hemat Ruang      : ${formatBytes(wastedBytes)} (${wastedBytes.toLocaleString()} bytes)`);
  console.log(divider);

  // STG-03 Output
  console.log('\n[!] DAFTAR FILE RAKSASA (GIANT FILES >= 2.048 KB):');
  console.log(subDivider);
  if (giantFiles.length === 0) {
    console.log('  Tidak ditemukan file raksasa di atas 2 MB.');
  } else {
    giantFiles.forEach((f, idx) => {
      const kb = (f.sizeBytes / 1024).toFixed(0);
      const mb = (f.sizeBytes / (1024 * 1024)).toFixed(2);
      console.log(`  ${(idx + 1).toString().padStart(2, ' ')}. ${f.name}`);
      console.log(`      Ukuran : ${mb} MB (${kb} KB / ${f.sizeBytes.toLocaleString()} bytes)`);
      console.log(`      Lokasi : ${f.relativePath}`);
    });
  }

  // STG-02 Output
  console.log('\n[!] DAFTAR KELOMPOK FILE DUPLIKAT (SHA-256 IDENTIK):');
  console.log(subDivider);
  if (duplicateGroups.length === 0) {
    console.log('  Tidak ditemukan file duplikat.');
  } else {
    duplicateGroups.forEach((grp, idx) => {
      console.log(`  [Kelompok ${idx + 1}] SHA-256: ${grp.hash.substring(0, 16)}... | Ukuran: ${formatBytes(grp.sizeBytes)} per file`);
      console.log(`    [ASLI DIPERTAHANKAN] : ${grp.original.name} (${grp.original.relativePath})`);
      grp.duplicates.forEach(dup => {
        console.log(`    [SALINAN DUPLIKAT]   : ${dup.name} (${dup.relativePath})`);
      });
      console.log('');
    });
  }

  console.log(divider);
  return { wastedBytes, totalDuplicateCopies };
}

/**
 * STG-05: Safe Cleanup Confirmation
 */
function promptCleanup(duplicateGroups, tmpFiles) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(
      '\nApakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ',
      answer => {
        rl.close();
        const trimmed = answer.trim().toUpperCase();

        if (trimmed === 'Y') {
          console.log('\n[+] Melakukan pembersihan file duplikat dan sampah secara aman...');
          let deletedCount = 0;
          let freedBytes = 0;

          // Hapus file salinan duplikat
          for (const grp of duplicateGroups) {
            for (const dup of grp.duplicates) {
              if (AUDIT_SCRIPT_FILES.has(dup.name.toLowerCase())) {
                console.log(`  [LEWATI] File dilindungi: ${dup.name}`);
                continue;
              }
              try {
                if (fs.existsSync(dup.fullPath)) {
                  fs.unlinkSync(dup.fullPath);
                  deletedCount++;
                  freedBytes += dup.sizeBytes;
                  console.log(`  [DIHAPUS] Salinan: ${dup.name}`);
                }
              } catch (err) {
                console.error(`  [GAGAL] Gagal menghapus ${dup.name}: ${err.message}`);
              }
            }
          }

          // Hapus file .tmp sampah
          for (const tmp of tmpFiles) {
            if (AUDIT_SCRIPT_FILES.has(tmp.name.toLowerCase())) continue;
            try {
              if (fs.existsSync(tmp.fullPath)) {
                fs.unlinkSync(tmp.fullPath);
                deletedCount++;
                freedBytes += tmp.sizeBytes;
                console.log(`  [DIHAPUS] File Sampah: ${tmp.name}`);
              }
            } catch (err) {
              console.error(`  [GAGAL] Gagal menghapus sampah ${tmp.name}: ${err.message}`);
            }
          }

          console.log('\n======================================================================');
          console.log(`  PEMBERSIHAN SELESAI!`);
          console.log(`  Total file dihapus : ${deletedCount} file`);
          console.log(`  Ruang dibebaskan   : ${formatBytes(freedBytes)} (${freedBytes.toLocaleString()} bytes)`);
          console.log('======================================================================\n');
          resolve(true);
        } else {
          console.log('\n[i] Pembatalan aman (Safe Cancel): Tidak ada file yang dihapus.\n');
          resolve(false);
        }
      }
    );
  });
}

/**
 * Menentukan target folder yang dipindai
 */
function resolveTargetDirectory() {
  const cliArg = process.argv[2];

  if (cliArg) {
    if (fs.existsSync(cliArg)) return cliArg;
    // Cek kemungkinan path relatif atau nama folder
    const resolved = path.resolve(cliArg);
    if (fs.existsSync(resolved)) return resolved;
  }

  // Default prioritas: folder "Bahan Latihan P12" jika ada, jika tidak gunakan current directory
  const defaultP12 = path.join(process.cwd(), 'Bahan Latihan P12');
  if (fs.existsSync(defaultP12)) return defaultP12;

  const parentP12 = path.join(process.cwd(), '..', 'Bahan Latihan P12');
  if (fs.existsSync(parentP12)) return parentP12;

  return '.';
}

/**
 * Main Execution
 */
async function main() {
  const targetDir = resolveTargetDirectory();

  if (!fs.existsSync(targetDir)) {
    console.error(`[ERROR] Direktori target "${targetDir}" tidak ditemukan.`);
    process.exit(1);
  }

  console.log(`\nMemindai folder: "${path.resolve(targetDir)}" ...`);

  // STG-01: Recursive Scan
  const rawFiles = await scanDirectory(targetDir);

  // Filter file skrip itu sendiri agar tidak mengganggu hasil audit
  const files = rawFiles.filter(f => !AUDIT_SCRIPT_FILES.has(f.name.toLowerCase()));

  // Deteksi file .tmp sampah
  const tmpFiles = files.filter(f => f.name.toLowerCase().endsWith('.tmp'));

  // STG-02: Duplicate Detection
  const duplicateGroups = detectDuplicates(files);

  // STG-03: Giant File Flagging
  const giantFiles = detectGiantFiles(files);

  // STG-04: Terminal Report
  printReport(targetDir, files, duplicateGroups, giantFiles, tmpFiles);

  // STG-05: Safe Cleanup Confirmation
  if (duplicateGroups.length > 0 || tmpFiles.length > 0) {
    await promptCleanup(duplicateGroups, tmpFiles);
  } else {
    console.log('[i] Tidak ditemukan file duplikat atau sampah untuk dibersihkan.');
  }
}

// Jalankan program
main().catch(err => {
  console.error('[ERROR FATAL]:', err);
  process.exit(1);
});
