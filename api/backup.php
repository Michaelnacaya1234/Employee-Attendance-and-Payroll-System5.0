<?php
// Backup & Data Management API
// Provides: listBackups, createBackup, downloadBackup, restoreFromFile, restoreUpload, deleteBackup

// Default to JSON except for download
header('Access-Control-Allow-Origin: *');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
  header('Access-Control-Allow-Headers: Content-Type');
  exit(0);
}

require_once __DIR__ . '/connection-pdo.php';

$operation = '';
$json = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $operation = isset($_GET['operation']) ? $_GET['operation'] : '';
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
  $json = isset($_POST['json']) ? $_POST['json'] : '';
}

// Settings
$BACKUP_DIR = __DIR__ . '/../backups';
if (!is_dir($BACKUP_DIR)) { @mkdir($BACKUP_DIR, 0777, true); }

switch ($operation) {
  case 'listBackups':
    requireAdmin();
    jsonHeader();
    echo json_encode(listBackups($BACKUP_DIR));
    break;
  case 'createBackup':
    requireAdmin();
    jsonHeader();
    echo json_encode(createBackup($conn, $BACKUP_DIR));
    break;
  case 'downloadBackup':
    requireAdmin();
    $file = isset($_GET['file']) ? basename($_GET['file']) : '';
    downloadBackup($BACKUP_DIR, $file);
    break;
  case 'restoreFromFile':
    requireAdmin();
    jsonHeader();
    $data = json_decode($json, true) ?: [];
    $file = isset($data['file']) ? basename($data['file']) : '';
    $path = realpath($BACKUP_DIR . '/' . $file);
    if (!$path || !is_file($path) || dirname($path) !== realpath($BACKUP_DIR)) {
      echo json_encode(['success' => false, 'message' => 'Invalid file']);
      break;
    }
    echo json_encode(restoreBackup($conn, $path));
    break;
  case 'restoreUpload':
    requireAdmin();
    jsonHeader();
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
      echo json_encode(['success' => false, 'message' => 'No file uploaded']);
      break;
    }
    $name = $_FILES['file']['name'];
    if (!preg_match('/\.sql$/i', $name)) {
      echo json_encode(['success' => false, 'message' => 'Only .sql files are allowed']);
      break;
    }
    $dest = $BACKUP_DIR . '/upload_' . date('Ymd_His') . '.sql';
    if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
      echo json_encode(['success' => false, 'message' => 'Failed to store uploaded file']);
      break;
    }
    $res = restoreBackup($conn, $dest);
    $res['stored_file'] = basename($dest);
    echo json_encode($res);
    break;
  case 'deleteBackup':
    requireAdmin();
    jsonHeader();
    $data = json_decode($json, true) ?: [];
    $file = isset($data['file']) ? basename($data['file']) : '';
    $path = realpath($BACKUP_DIR . '/' . $file);
    if (!$path || !is_file($path) || dirname($path) !== realpath($BACKUP_DIR)) {
      echo json_encode(['success' => false, 'message' => 'Invalid file']);
      break;
    }
    @unlink($path);
    echo json_encode(['success' => true]);
    break;
  default:
    jsonHeader();
    echo json_encode(['success' => false, 'message' => 'Invalid operation']);
}

function jsonHeader() { header('Content-Type: application/json'); }

function requireAdmin() {
  if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    jsonHeader();
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
  }
}

/**
 * LIST AVAILABLE BACKUP FILES
 * Scans backup directory for SQL files and returns file metadata
 * Sorted by creation date for easy identification of latest backups
 */
function listBackups($dir) {
  $out = [];
  if (!is_dir($dir)) return $out;
  $dh = opendir($dir);
  if (!$dh) return $out;
  while (($f = readdir($dh)) !== false) {
    if ($f === '.' || $f === '..') continue;
    if (!preg_match('/\.sql$/i', $f)) continue;
    $path = $dir . '/' . $f;
    if (is_file($path)) {
      $out[] = [
        'file' => $f,
        'size' => filesize($path),
        'created_at' => date('Y-m-d H:i:s', filemtime($path))
      ];
    }
  }
  closedir($dh);
  // Sort by newest first
  usort($out, function($a, $b){ return strcmp($b['created_at'], $a['created_at']); });
  return $out;
}

/**
 * CREATE COMPLETE DATABASE BACKUP
 * Generates SQL dump of all tables with structure and data
 * Includes transaction safety and foreign key management
 */
function createBackup($conn, $dir) {
  try {
    $dbname = getDbName($conn);
    $filename = 'backup_' . date('Ymd_His') . '.sql';
    $path = $dir . '/' . $filename;

    $tables = [];
    $q = $conn->query('SHOW TABLES');
    while ($row = $q->fetch(PDO::FETCH_NUM)) { $tables[] = $row[0]; }

    $dump = [];
    $dump[] = '-- Database Backup';
    $dump[] = '-- Generated: ' . date('c');
    $dump[] = "SET NAMES utf8mb4;";
    $dump[] = "SET FOREIGN_KEY_CHECKS=0;";
    $dump[] = "START TRANSACTION;";
    if ($dbname) { $dump[] = "USE `" . str_replace('`','``',$dbname) . "`;"; }

    foreach ($tables as $table) {
      // DROP + CREATE
      $dump[] = "\n-- \n-- Structure for table `" . $table . "`\n-- ";
      $dump[] = "DROP TABLE IF EXISTS `" . str_replace('`','``',$table) . "`;";
      $stmt = $conn->query("SHOW CREATE TABLE `" . str_replace('`','``',$table) . "`");
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      $create = $row && isset($row['Create Table']) ? $row['Create Table'] : null;
      if (!$create) { // MySQL 8 alias key sometimes different case
        $vals = array_values($row ?: []);
        $create = isset($vals[1]) ? $vals[1] : '';
      }
      $dump[] = $create . ";";

      // Data
      $dataQ = $conn->query("SELECT * FROM `" . str_replace('`','``',$table) . "`");
      $cols = [];
      for ($i=0; $i < $dataQ->columnCount(); $i++) {
        $meta = $dataQ->getColumnMeta($i);
        $cols[] = $meta['name'];
      }
      $rowsChunk = [];
      while ($row = $dataQ->fetch(PDO::FETCH_ASSOC)) {
        $vals = [];
        foreach ($cols as $c) {
          $v = array_key_exists($c, $row) ? $row[$c] : null;
          if ($v === null) $vals[] = 'NULL'; else $vals[] = $conn->quote($v);
        }
        $rowsChunk[] = '(' . implode(',', $vals) . ')';
        if (count($rowsChunk) >= 1000) {
          $dump[] = buildInsert($table, $cols, $rowsChunk);
          $rowsChunk = [];
        }
      }
      if (!empty($rowsChunk)) {
        $dump[] = buildInsert($table, $cols, $rowsChunk);
      }
    }

    $dump[] = 'COMMIT;';
    $dump[] = 'SET FOREIGN_KEY_CHECKS=1;';

    $ok = file_put_contents($path, implode("\n", $dump));
    if ($ok === false) return ['success' => false, 'message' => 'Failed to write file'];

    auditLog($conn, 'create_backup', 'Created backup ' . $filename);
    return ['success' => true, 'file' => $filename];
  } catch (Exception $e) {
    return ['success' => false, 'message' => 'Backup failed'];
  }
}

/**
 * HELPER: BUILD INSERT STATEMENT
 * Constructs batch INSERT statements for backup data
 * Handles proper escaping and formatting for SQL dumps
 */
function buildInsert($table, $cols, $rows) {
  $colsEsc = array_map(function($c){ return '`' . str_replace('`','``',$c) . '`'; }, $cols);
  return 'INSERT INTO `' . str_replace('`','``',$table) . '` (' . implode(',', $colsEsc) . ') VALUES ' . implode(",\n", $rows) . ';';
}

/**
 * DOWNLOAD BACKUP FILE
 * Serves backup file with proper headers for download
 * Includes security validation to prevent directory traversal
 */
function downloadBackup($dir, $file) {
  $path = realpath($dir . '/' . $file);
  if (!$file || !$path || !is_file($path) || dirname($path) !== realpath($dir)) {
    jsonHeader();
    echo json_encode(['success' => false, 'message' => 'Invalid file']);
    return;
  }
  header('Content-Type: application/octet-stream');
  header('Content-Disposition: attachment; filename="' . basename($path) . '"');
  header('Content-Length: ' . filesize($path));
  readfile($path);
}

/**
 * RESTORE DATABASE FROM BACKUP FILE
 * Completely replaces current database with backup data
 * Handles transactions and provides detailed error messages
 */
function restoreBackup($conn, $path) {
  try {
    $conn->beginTransaction();
    $conn->exec('SET FOREIGN_KEY_CHECKS=0');

    $handle = fopen($path, 'r');
    if (!$handle) throw new Exception('Cannot open backup file');

    $buffer = '';
    while (($line = fgets($handle)) !== false) {
      $trim = trim($line);
      if ($trim === '' || strpos($trim, '--') === 0) continue; // skip comments and blanks
      // rudimentary handling: ignore multi-line comments
      if (strpos($trim, '/*') === 0) {
        while ($line !== false && strpos($line, '*/') === false) { $line = fgets($handle); }
        continue;
      }
      $buffer .= $line;
      if (substr(rtrim($line), -1) === ';') {
        $conn->exec($buffer);
        $buffer = '';
      }
    }
    fclose($handle);

    $conn->exec('SET FOREIGN_KEY_CHECKS=1');
    $conn->commit();

    auditLog($conn, 'restore_backup', 'Restored from ' . basename($path));
    return ['success' => true];
  } catch (Exception $e) {
    if ($conn->inTransaction()) $conn->rollBack();
    $errorMsg = $e->getMessage();
    // Provide more specific error messages for common issues
    if (strpos($errorMsg, 'Access denied') !== false) {
      $errorMsg = 'Database access denied - check permissions';
    } elseif (strpos($errorMsg, 'Unknown database') !== false) {
      $errorMsg = 'Database not found';
    } elseif (strpos($errorMsg, 'Table') !== false && strpos($errorMsg, "doesn't exist") !== false) {
      $errorMsg = 'Invalid backup file - table structure mismatch';
    } elseif (strpos($errorMsg, 'Duplicate entry') !== false) {
      $errorMsg = 'Duplicate data detected - restore may have been partially completed';
    } elseif (strpos($errorMsg, 'Cannot open') !== false) {
      $errorMsg = 'Cannot read backup file - file may be corrupted';
    } elseif (empty($errorMsg)) {
      $errorMsg = 'Restore failed - unknown error occurred';
    }
    return ['success' => false, 'message' => $errorMsg];
  }
}

/**
 * LOG BACKUP/RESTORE ACTIONS TO AUDIT TRAIL
 * Records backup operations for security and compliance
 * Includes user, action, and IP address information
 */
function auditLog($conn, $action, $details) {
  try {
    $uid = isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $conn->prepare("INSERT INTO tblaudit_logs (user_id, action, details, ip_address) VALUES (:uid, :action, :details, :ip)");
    $stmt->bindParam(':uid', $uid, PDO::PARAM_INT);
    $stmt->bindParam(':action', $action);
    $stmt->bindParam(':details', $details);
    $stmt->bindParam(':ip', $ip);
    $stmt->execute();
  } catch (Exception $e) { /* ignore */ }
}

/**
 * HELPER: GET DATABASE NAME
 * Retrieves current database name from connection
 * Used for backup SQL generation and validation
 */
function getDbName($conn) {
  try { return $conn->query('SELECT DATABASE()')->fetchColumn(); } catch (Exception $e) { return null; }
}
