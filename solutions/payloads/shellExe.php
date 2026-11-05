<?php
echo "<pre>";
if (function_exists("shell_exec")) {
    echo htmlspecialchars(shell_exec("whoami") ?? "");
} else {
    echo "shell_exec is disabled";
}
echo "</pre>";
?>