<?php
header("Content-Security-Policy: script-src 'self';");
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Reflected XSS Test</title>
</head>
<body>
  <h2>Search</h2>
  <form action="test.php" method="GET">
    <input type="text" name="term">
    <button type="submit">Search</button>
  </form>

  <?php
    if (isset($_GET['term'])) {
      echo "<p>You searched for: ".$_GET['term']."</p>";
    }
  ?>
</body>
</html>