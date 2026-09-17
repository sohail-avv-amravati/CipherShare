<?php
use Auth\AuthManager;
$currentUser = AuthManager::getCurrentUser();
?>
<?php if ($currentUser && !(isset($isOwnerPage) && $isOwnerPage)): ?>
    </div><!-- /.content-area -->
  </div><!-- /.main-content -->
</div><!-- /.app-layout -->
<?php else: ?>
    </div><!-- /.container -->
  </main><!-- /.public-main -->
<?php endif; ?>

<footer class="site-footer">
  <div class="container text-center">
    <p>&copy; <?= date('Y') ?> CipherShare — Authenticated Encrypted Storage & Expiration Sharing</p>
  </div>
</footer>
</body>
</html>
