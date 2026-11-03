<?php
/**
 * Composer post-install/update hook: removes demo code that vendored packages
 * ship but a plugin must not (lbuchs/webauthn's _test/ holds a runnable
 * server.php). Run by `composer install` / `composer update`.
 */
$dirs = [__DIR__ . '/../vendor/lbuchs/webauthn/_test'];
foreach ($dirs as $dir) {
    if (!is_dir($dir)) {
        continue;
    }
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($dir);
}
