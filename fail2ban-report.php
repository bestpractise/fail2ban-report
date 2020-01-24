<?php
/* This file is part of the Fail2ban Report (fail2ban-report) package
 * (c) BestPractise.net <info-at-bestpractise.net>
 *
 * View README and CHANGELOG distributed with this code for more information.
 */

/**
 * This file is constructed in a few sections:
 *      1. Parser functions around fail2ban-report.sh
 *      2. Classes for combining extracted config (Fail2banState, Fail2banJail)
 *      3. Output in HTML/CSS (based on Bootstrap 4.4)
 */

/**
 * Parser functions around fail2ban-report.sh
 *
 * The following function a parsing wrappers around the accompanied script
 * fail2ban-report.sh. That scripts is an abstract layer added for security to
 * safely facilitate shell access by PHP.
 */
function getStatus() {
    $statusOutput = shell_exec("sudo /usr/bin/f2bstatus.sh status");
    $statusOutputParts = explode(PHP_EOL, rtrim($statusOutput));
    $jailsLine = array_pop($statusOutputParts);
    $jailsLine = str_replace("`- Jail list:", "", $jailsLine);
    $jailsParts = explode(",", trim($jailsLine));
    $jails = [];
    foreach ($jailsParts as $jail) {
        $jails[] = trim($jail);
    }
    return $jails;
}

function getLogLevel() {
    $logLevelOutput = shell_exec("sudo /usr/bin/f2bstatus.sh loglevel");
    if (strpos($logLevelOutput, "INFO")) {
        return "INFO";
    } else {
        return "Unknown loglevel";
    }
}

function getDbFile() {
    $dbFileOutput = shell_exec("sudo /usr/bin/f2bstatus.sh dbfile");
    $dbFileParts = explode(PHP_EOL, rtrim($dbFileOutput));
    $dbFileLine = array_pop($dbFileParts);
    $dbFileLine = str_replace("`-", "", $dbFileLine);
    $dbFile = trim($dbFileLine);
    return $dbFile;
}

function getDbPurgeAge() {
    $dbPurgeAgeOutput = shell_exec("sudo /usr/bin/f2bstatus.sh dbpurgeage");
    $dbPurgeAgeParts = explode(PHP_EOL, rtrim($dbPurgeAgeOutput));
    $dbPurgeAgeLine = array_pop($dbPurgeAgeParts);
    $dbPurgeAgeLine = str_replace("`-", "", $dbPurgeAgeLine);
    $dbPurgeAge = trim($dbPurgeAgeLine);
    return $dbPurgeAge;
}

function getLogTarget() {
    $logTargetOutput = shell_exec("sudo /usr/bin/f2bstatus.sh logtarget");
    $logTargetParts = explode(PHP_EOL, rtrim($logTargetOutput));
    $logTargetLine = array_pop($logTargetParts);
    $logTargetLine = str_replace("`-", "", $logTargetLine);
    $logTarget = trim($logTargetLine);
    return $logTarget;
}

function getSyslogSocket() {
    $syslogSocketOutput = shell_exec("sudo /usr/bin/f2bstatus.sh syslogsocket");
    $syslogSocketParts = explode(PHP_EOL, rtrim($syslogSocketOutput));
    $syslogSocketLine = array_pop($syslogSocketParts);
    $syslogSocketLine = str_replace("`-", "", $syslogSocketLine);
    $syslogSocket = trim($syslogSocketLine);
    return $syslogSocket;
}

function getJailBanTime($jailName) {
    $banTimeOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail bantime " . $jailName);
    $banTime = trim($banTimeOutput);
    return $banTime;
}

function getJailFindTime($jailName) {
    $findTimeOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail findtime " . $jailName);
    $findTime = trim($findTimeOutput);
    return $findTime;
}

function getJailIgnoreIp($jailName) {
    $ignoreIpOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail ignoreip " . $jailName);
    if (trim($ignoreIpOutput) == "No IP address/network is ignored") {
        return [];
    }
    $ignoreIpParts = explode(PHP_EOL, rtrim($ignoreIpOutput));
    array_push($ignoreIpParts);
    $ignoreIps = [];
    foreach ($ignoreIpParts as $ignoreIpPart) {
        $ignoreIpPart = str_replace("|-", "", $ignoreIpPart);
        $ignoreIpPart = str_replace("`-", "", $ignoreIpPart);
        $ignoreIps[] = trim($ignoreIpPart);
    }
    return $ignoreIps;
}

function getJailIgnoreSelf($jailName) {
    $ignoreSelfOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail ignoreself " . $jailName);
    $ignoreSelf = trim($ignoreSelfOutput);
    return $ignoreSelf;
}

function getJailJournalMatch($jailName) {
    $journalMatchOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail journalmatch " . $jailName);
    $journalMatch = trim($journalMatchOutput);
    return $journalMatch;
}

function getJailLogPath($jailName) {
    $logPathOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail logpath " . $jailName);
    $logPathParts = explode(PHP_EOL, rtrim($logPathOutput));
    $logPathLine = array_pop($logPathParts);
    $logPathLine = str_replace("`-", "", $logPathLine);
    $logPath = trim($logPathLine);
    return $logPath;
}

function getJailLogEncoding($jailName) {
    $logEncodingOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail logencoding " . $jailName);
    $logEncodingParts = explode(PHP_EOL, rtrim($logEncodingOutput));
    $logEncodingLine = array_pop($logEncodingParts);
    $logEncoding = trim($logEncodingLine);
    return $logEncoding;
}

function getJailMaxLines($jailName) {
    $maxLinesOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail maxlines " . $jailName);
    $maxLines = trim($maxLinesOutput);
    return $maxLines;
}

function getJailMaxRetry($jailName) {
    $maxRetryOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail maxretry " . $jailName);
    $maxRetry = trim($maxRetryOutput);
    return $maxRetry;
}

function getJailUseDns($jailName) {
    $useDnsOutput = shell_exec("sudo /usr/bin/f2bstatus.sh jail usedns " . $jailName);
    $useDns = trim($useDnsOutput);
    return $useDns;
}

/**
 * Classes for combining extracted config
 *
 * The following classes define the configuration schema of fail2ban. The
 * classes are used to combine all extracted configuration into a logical
 * hierarchy. This will be rendered into a HTML view at the and of this script.
 */
class Fail2banState {
    /** @var Fail2banJail[] */
    public $jails;
    public $dbFile;
    public $dbPurgeAge;
    public $logLevel;
    public $logTarget;
    public $syslogSocket;

    public function addJail(Fail2banJail $jail) {
        $this->jails[] = $jail;
    }

    public function setDbFile(string $dbFile) {
        $this->dbFile = $dbFile;
    }

    public function setDbPurgeAge(string $dbPurgeAge) {
        $this->dbPurgeAge = $dbPurgeAge;
    }

    public function setLogLevel(string $logLevel) {
        $this->logLevel = $logLevel;
    }

    public function setLogTarget(string $logTarget) {
        $this->logTarget = $logTarget;
    }

    public function setSyslogSocket(string $syslogSocket) {
        $this->syslogSocket = $syslogSocket;
    }
}

class Fail2banJail {
    public $name;
    public $banTime;
    public $findTime;
    public $ignoreIp;
    public $ignoreSelf;
    public $journalMatch;
    public $logEncoding;
    public $logPath;
    public $maxLines;
    public $maxRetry;
    public $useDns;

    public function __construct(string $name) {
        $this->name = $name;
    }

    public function setBanTime(string $banTime) {
        $this->banTime = $banTime;
    }

    public function setFindTime(string $findTime) {
        $this->findTime = $findTime;
    }

    public function setIgnoreIp(array $ignoreIp) {
        $this->ignoreIp = $ignoreIp;
    }

    public function setIgnoreSelf(string $ignoreSelf) {
        $this->ignoreSelf = $ignoreSelf;
    }

    public function setJournalMatch(string $journalMatch) {
        $this->journalMatch = $journalMatch;
    }

    public function setLogEncoding(string $logEncoding) {
        $this->logEncoding = $logEncoding;
    }

    public function setLogPath(string $logPath) {
        $this->logPath = $logPath;
    }

    public function setMaxLines(string $maxLines) {
        $this->maxLines = $maxLines;
    }

    public function setMaxRetry(string $maxRetry) {
        $this->maxRetry = $maxRetry;
    }

    public function setUseDns(string $useDns) {
        $this->useDns = $useDns;
    }
}

$fail2ban = new Fail2banState();
foreach (getStatus() as $jailName) {
    $fail2ban->addJail(new Fail2banJail($jailName));
}
$fail2ban->setDbFile(getDbFile());
$fail2ban->setDbPurgeAge(getDbPurgeAge());
$fail2ban->setLogLevel(getLogLevel());
$fail2ban->setLogTarget(getLogTarget());
$fail2ban->setSyslogSocket(getSyslogSocket());

foreach ($fail2ban->jails as &$jail) {
    $jail->setBanTime(getJailBanTime($jail->name));
    $jail->setFindTime(getJailFindTime($jail->name));
    $jail->setIgnoreIp(getJailIgnoreIp($jail->name));
    $jail->setIgnoreSelf(getJailIgnoreSelf($jail->name));
    $jail->setJournalMatch(getJailJournalMatch($jail->name));
    $jail->setLogEncoding(getJailLogEncoding($jail->name));
    $jail->setLogPath(getJailLogPath($jail->name));
    $jail->setMaxLines(getJailMaxLines($jail->name));
    $jail->setMaxRetry(getJailMaxRetry($jail->name));
    $jail->setUseDns(getJailUseDns($jail->name));
}

/**
 * Output in HTML/CSS (based on Bootstrap 4.4)
 *
 * Extracted configuration of fail2ban now will be rendered into a HTML/CSS view
 * based on Bootstrap.
 */
?>
<!doctype html>
<html lang='en'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
    <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css'
          integrity='sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh' crossorigin='anonymous'>
    <title>Fail2ban Report - by BestPractise.net</title>
</head>
<body>
<nav class='navbar navbar-expand-lg navbar-light bg-light'>
    <a class='navbar-brand' href='#'>Fail2ban Report</a>
    <div class='collapse navbar-collapse'>
        <ul class='navbar-nav mr-auto'>
            <li class='nav-item active'><a class='nav-link active' href='#'>Home <span class='sr-only'>(current)</span></a>
            </li>
        </ul>
        <span class='navbar-text'>by BestPractise.net</span>
    </div>
</nav>
<div class='container-fluid'>
    <h2>Fail2ban main configuration</h2>
    <div class='row'>
        <div class='col-md-6'>
            <table class='table table-sm'>
                <tr>
                    <td>Database file:</td>
                    <td><samp><?= $fail2ban->dbFile ?></samp></td>
                </tr>
                <tr>
                    <td>Database purge age:</td>
                    <td><?= $fail2ban->dbPurgeAge ?></td>
                </tr>
                <tr>
                    <td>Log level:</td>
                    <td><?= $fail2ban->logLevel ?></td>
                </tr>
                <tr>
                    <td>Log target:</td>
                    <td><samp><?= $fail2ban->logTarget ?></samp></td>
                </tr>
                <tr>
                    <td>Syslog socket:</td>
                    <td><?= $fail2ban->syslogSocket ?></td>
                </tr>
            </table>
        </div>
        <div class='col-md-6'>
            <table class='table table-sm'>
                <tr>
                    <td>Jails:</td>
                    <td><?= count($fail2ban->jails) ?></td>
                </tr>
            </table>
        </div>
    </div>
    <?php
    foreach ($fail2ban->jails as $jail) {
        ?>
        <div class='card'>
            <div class='card-header'><?= $jail->name ?></div>
            <table class='table table-sm'>
                <tr>
                    <td>Ban time:</td>
                    <td><?= $jail->banTime ?></td>
                </tr>
                <tr>
                    <td>Find time:</td>
                    <td><?= $jail->findTime ?></td>
                </tr>
                <tr>
                    <td>Ignore ip:</td>
                    <td><?= implode(", ", $jail->ignoreSelf) ?></td>
                </tr>
                <tr>
                    <td>Ignore self:</td>
                    <td><?= $jail->ignoreSelf ?></td>
                </tr>
                <tr>
                    <td>Journal match:</td>
                    <td><?= $jail->journalMatch ?></td>
                </tr>
                <tr>
                    <td>Log encoding:</td>
                    <td><?= $jail->logEncoding ?></td>
                </tr>
                <tr>
                    <td>Log path:</td>
                    <td><?= $jail->logPath ?></td>
                </tr>
                <tr>
                    <td>Max lines:</td>
                    <td><?= $jail->maxLines ?></td>
                </tr>
                <tr>
                    <td>Max retry:</td>
                    <td><?= $jail->maxRetry ?></td>
                </tr>
                <tr>
                    <td>Use DNS:</td>
                    <td><?= $jail->useDns ?></td>
                </tr>
            </table>
        </div>
        <?php
    }
    ?>
</div>
<script src='https://code.jquery.com/jquery-3.4.1.slim.min.js'
        integrity='sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n'
        crossorigin='anonymous'></script>
<script src='https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js'
        integrity='sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo'
        crossorigin='anonymous'></script>
<script src='https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js'
        integrity='sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6'
        crossorigin='anonymous'></script>
</body>
</html>