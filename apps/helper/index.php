<?php
$files = glob(__DIR__ . '/patchday_*.html');
rsort($files);
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Patchday Reports</title>
<link rel="stylesheet" href="css/style.css">
<link rel="stylesheet" href="css/fonts/fonts.css">
<style>
  body { font-family: 'Inter', sans-serif; background: #0a0c10; color: #e2e8f0; padding: 30px; }
  .container { max-width: 800px; margin: 0 auto; background: #12161f; border: 1px solid rgba(0,247,255,0.2); border-radius: 8px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
  h1 { color: #00f7ff; border-bottom: 2px solid rgba(0,247,255,0.3); padding-bottom: 10px; font-family: 'Fira Code', monospace; }
  ul { list-style: none; padding: 0; }
  li { padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
  li:last-child { border-bottom: none; }
  a { color: #00f7ff; text-decoration: none; font-size: 16px; font-family: 'Fira Code', monospace; }
  a:hover { text-decoration: underline; }
  .meta { font-size: 13px; color: #94a3b8; margin-top: 3px; font-family: 'Fira Code', monospace; }
  .btn { display: inline-block; margin-top: 20px; padding: 10px 20px; background: transparent; color: #00f7ff; border: 1px solid #00f7ff; border-radius: 4px; text-decoration: none; font-family: 'Fira Code', monospace; transition: all 0.2s; }
  .btn:hover { background: rgba(0, 247, 255, 0.1); text-decoration: none; box-shadow: 0 0 10px rgba(0,247,255,0.3); }
  .empty { color: #94a3b8; font-style: italic; }
</style>
</head>
<body>
<div class="container">
  <h1>Patchday Reports</h1>
  <?php if (empty($files)): ?>
    <p class="empty">Noch keine Reports vorhanden.</p>
  <?php else: ?>
  <ul>
    <?php foreach ($files as $f):
      $name = basename($f);
      $mtime = filemtime($f);
      $date = date('d.m.Y H:i', $mtime);
    ?>
    <li>
      <a href="<?= htmlspecialchars($name) ?>"><?= htmlspecialchars($name) ?></a>
      <div class="meta">Erstellt: <?= $date ?> &bull; <?= round(filesize($f)/1024, 1) ?> KB</div>
    </li>
    <?php endforeach; ?>
  </ul>
  <?php endif; ?>
  <a href="baselinevulnboard.html" class="btn">&#8594; Report Generator</a>
</div>
</body>
</html>
