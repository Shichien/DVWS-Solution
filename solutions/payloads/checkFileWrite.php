<?php
$path = sys_get_temp_dir() . "/dvwa_test.txt";
$result = file_put_contents($path, "Hello from DVWA!");
if ($result !== false) {
    echo "Write successful!";
    echo "<pre>" . htmlspecialchars(file_get_contents($path)) . "</pre>";
} else {
    echo "Write failed!";
}
?>