<?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');

  if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
  }

  require_once __DIR__ . '/connection-pdo.php';

  $operation = '';
  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $operation = isset($_GET['operation']) ? $_GET['operation'] : 'getTheme';
  } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
  }

  switch ($operation) {
    case 'setTheme':
      echo setTheme($conn);
      break;
    case 'getTheme':
    default:
      echo getTheme($conn);
      break;
  }

  /**
   * RETRIEVE CURRENT THEME SETTINGS
   * Fetches UI theme configuration from database
   * Returns theme name and color values with defaults
   */
  function getTheme($conn) {
    $defaults = [
      'ui_theme' => 'blue',
      'ui_theme_primary_600' => '#2563eb',
      'ui_theme_primary_700' => '#1d4ed8',
    ];

    try {
      $stmt = $conn->prepare("SELECT setting_key, setting_value FROM tblsystem_settings WHERE setting_key IN ('ui_theme','ui_theme_primary_600','ui_theme_primary_700')");
      $stmt->execute();
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $settings = [];
      foreach ($rows as $row) { $settings[$row['setting_key']] = $row['setting_value']; }
      foreach ($defaults as $k => $v) { if (!isset($settings[$k]) || $settings[$k] === null || $settings[$k] === '') $settings[$k] = $v; }
      return json_encode([
        'success' => true,
        'theme' => $settings['ui_theme'],
        'primary_600' => $settings['ui_theme_primary_600'],
        'primary_700' => $settings['ui_theme_primary_700'],
      ]);
    } catch (Exception $e) {
      return json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
  }

  /**
   * UPDATE THEME CONFIGURATION
   * Sets UI theme colors and style preferences
   * Validates color values and updates system settings
   */
  function setTheme($conn) {
    $palette = [
      'blue' => ['#2563eb', '#1d4ed8'],
      'emerald' => ['#059669', '#047857'],
      'rose' => ['#e11d48', '#be123c'],
      'violet' => ['#7c3aed', '#6d28d9'],
      'amber' => ['#d97706', '#b45309'],
      'teal' => ['#0d9488', '#0f766e'],
    ];

    $data = [];
    if (isset($_POST['json'])) {
      $data = json_decode($_POST['json'], true);
    } else {
      $raw = file_get_contents('php://input');
      if ($raw) { $tmp = json_decode($raw, true); if (is_array($tmp)) $data = $tmp; }
    }
    if (!is_array($data)) $data = [];

    $theme = isset($data['theme']) ? trim($data['theme']) : '';
    $p600 = isset($data['primary_600']) ? trim($data['primary_600']) : '';
    $p700 = isset($data['primary_700']) ? trim($data['primary_700']) : '';

    if ($theme && isset($palette[$theme])) {
      $p600 = $palette[$theme][0];
      $p700 = $palette[$theme][1];
    }

    // Validate hex colors (simple)
    $isHex = function($s){ return is_string($s) && preg_match('/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/', $s); };

    if (!$p600 || !$isHex($p600) || !$p700 || !$isHex($p700)) {
      return json_encode(['success' => false, 'error' => 'Invalid or missing primary colors']);
    }

    if (!$theme) {
      // If not provided or custom colors, set theme name to custom
      $theme = 'custom';
    }

    try {
      $conn->beginTransaction();
      upsertSetting($conn, 'ui_theme', $theme);
      upsertSetting($conn, 'ui_theme_primary_600', $p600);
      upsertSetting($conn, 'ui_theme_primary_700', $p700);
      $conn->commit();
      return json_encode(['success' => true, 'theme' => $theme, 'primary_600' => $p600, 'primary_700' => $p700]);
    } catch (Exception $e) {
      try { $conn->rollBack(); } catch (Exception $ie) {}
      return json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
  }

  /**
   * HELPER: UPSERT SYSTEM SETTING
   * Inserts or updates individual setting value
   * Used for atomic theme configuration updates
   */
  function upsertSetting($conn, $key, $value) {
    $sql = "INSERT INTO tblsystem_settings (setting_key, setting_value) VALUES (:k, :v)
            ON DUPLICATE KEY UPDATE setting_value = :v";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':k', $key);
    $stmt->bindParam(':v', $value);
    $stmt->execute();
  }
?>
