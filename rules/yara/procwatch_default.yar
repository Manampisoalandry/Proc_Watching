rule ProcWatch_ReverseShell_Indicators
{
  meta:
    description = "Generic reverse shell indicators in scripts/commands"
    author = "ProcWatch"
  strings:
    $devtcp = "/dev/tcp/" ascii
    $mkfifo = "mkfifo" ascii
    $socat = "socat" ascii
    $nce = " nc -e " ascii
    $ncc = " nc -c " ascii
    $bash_i = "bash -i" ascii
  condition:
    2 of them
}

rule ProcWatch_Download_Execute
{
  meta:
    description = "Download and execute patterns"
    author = "ProcWatch"
  strings:
    $curlpipe = /curl\s+[^|]+\|\s*(sh|bash)/ nocase
    $wgetpipe = /wget\s+[^|]+\|\s*(sh|bash)/ nocase
  condition:
    any of them
}

rule ProcWatch_Miner_Strings
{
  meta:
    description = "Common miner strings"
    author = "ProcWatch"
  strings:
    $xmrig = "xmrig" ascii nocase
    $stratum = "stratum+tcp" ascii nocase
    $cryptonight = "cryptonight" ascii nocase
    $monero = "monero" ascii nocase
  condition:
    2 of them
}
