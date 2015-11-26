-- This is the main configuration file for Propellor, and is used to build
-- the propellor program.

import           Control.Applicative ((<$>), (<*>))
import           Propellor
import           Propellor.CmdLine
import qualified Propellor.Property.Apache as Apache
import qualified Propellor.Property.Apt as Apt
import qualified Propellor.Property.Chroot as Chroot
import qualified Propellor.Property.Cron as Cron
import qualified Propellor.Property.Debootstrap as Debootstrap
import qualified Propellor.Property.Docker as Docker
import qualified Propellor.Property.File as File
import qualified Propellor.Property.Hostname as Hostname
import qualified Propellor.Property.Nginx as Nginx
import qualified Propellor.Property.Postfix as Postfix
import qualified Propellor.Property.Ssh as Ssh
import qualified Propellor.Property.Sudo as Sudo
import qualified Propellor.Property.Systemd as Systemd
import qualified Propellor.Property.User as User
import           System.Posix.Files
import           Utility.FileMode

main :: IO ()
main = defaultMain hosts


-- The hosts propellor knows about.
-- Edit this to configure propellor!
hosts :: [Host]
hosts = [ scarlet
        , onyx
        ]


scarlet :: Host
scarlet = standardSystem "scarlet.fusionapp.com" (Stable "jessie") "amd64"
          & ipv4 "197.189.229.122"
          & fusionHost
          & Ssh.keyImported SshRsa (User "root") hostContext
          -- Local private certificates
          & File.dirExists "/srv/certs/private"
          & File.hasPrivContent "/srv/certs/private/fusiontest.net-fusionca.crt.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/scarlet.fusionapp.com.pem" hostContext
          & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/ca.crt" `File.isSymlinkedTo` "/srv/certs/public/fusion-ca.crt.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` "/srv/certs/private/scarlet.fusionapp.com.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` "/srv/certs/private/scarlet.fusionapp.com.pem"
          & Cron.niceJob "fusion-backup" (Cron.Times "23 * * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-eu-uat.fusionapp.com"


onyx :: Host
onyx = standardSystem "onyx.fusionapp.com" (Stable "jessie") "amd64"
       & ipv4 "41.72.130.249"
       & fusionHost
       -- Local private certificates
       & File.dirExists "/srv/certs/private"
       & File.hasPrivContent "/srv/certs/private/star.fusionapp.com.pem" hostContext
       & File.hasPrivContent "/srv/certs/private/onyx.fusionapp.com.pem" hostContext
       & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/ca.crt" `File.isSymlinkedTo` "/srv/certs/public/fusion-ca.crt.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` "/srv/certs/private/onyx.fusionapp.com.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` "/srv/certs/private/onyx.fusionapp.com.pem"
       & Systemd.nspawned nginxPrimary
       & Systemd.nspawned apacheSvn `requires` Systemd.running Systemd.networkd
       & Systemd.nspawned mailRelayContainer


fusionHost :: Property HasInfo
fusionHost = propertyList "Platform dependencies for Fusion services" $ props
             & "/etc/timezone" `File.hasContent` ["Africa/Johannesburg"]
             & Apt.installed ["mercurial", "git"]
             & Docker.installed
             & propertyList "admin docker access"
             (flip User.hasGroup (Group "docker") <$> admins)
             & File.dirExists "/srv/duplicity"
             & File.hasPrivContent "/srv/duplicity/credentials.sh" hostContext
             & File.dirExists "/srv/locks"
             & backupScript


fusionCa :: [String]
fusionCa =
  [ "-----BEGIN CERTIFICATE-----"
  , "MIIEFzCCAv+gAwIBAgIBATANBgkqhkiG9w0BAQUFADBqMQswCQYDVQQGEwJaQTEQ"
  , "MA4GA1UECAwHR2F1dGVuZzEVMBMGA1UEBwwMSm9oYW5uZXNidXJnMR4wHAYDVQQK"
  , "DBVGdXNpb24gRGVhbGVyIFN5c3RlbXMxEjAQBgNVBAMMCUZ1c2lvbiBDQTAeFw0x"
  , "NDEwMDYwNDA1NTZaFw0xOTEwMDYwNDA1NTZaMGoxCzAJBgNVBAYTAlpBMRAwDgYD"
  , "VQQIDAdHYXV0ZW5nMRUwEwYDVQQHDAxKb2hhbm5lc2J1cmcxHjAcBgNVBAoMFUZ1"
  , "c2lvbiBEZWFsZXIgU3lzdGVtczESMBAGA1UEAwwJRnVzaW9uIENBMIIBIjANBgkq"
  , "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1AmaUWaouyDOPf6kk9DaHuwRLg7WZQlR"
  , "TxLrY/Nn8dg0VlgVlRpNDzHcjH57VVh2ZVDoVs0hVRLPRXLFQMCPqG6QxawhZbAM"
  , "IETeDsaD1rRGOasUU5oS7DxDVPVDcJ0xr95cSjeism1CG/7joE2zzs6OaQlfgz27"
  , "G9h3OxaWrcYp9PIhYartbmBczgcjSXl5rf099ySJqIKtTS8rT51f7i9cXTw3Nf5g"
  , "Kpglyx+izsW/UlTAWpZ33zc7r27uzy5DdcRKihOxHxmjk4cyy+a1Nh8rWOfJ888U"
  , "0/hsKd/MWvvy/YREDtnZnEjP4Dl2OAh4/Dw/fW32LY7ttQpyt28WgQIDAQABo4HH"
  , "MIHEMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFJsTGGzEoH2UX4pSGAtH4ZIxKMSt"
  , "MIGUBgNVHSMEgYwwgYmAFJsTGGzEoH2UX4pSGAtH4ZIxKMStoW6kbDBqMQswCQYD"
  , "VQQGEwJaQTEQMA4GA1UECAwHR2F1dGVuZzEVMBMGA1UEBwwMSm9oYW5uZXNidXJn"
  , "MR4wHAYDVQQKDBVGdXNpb24gRGVhbGVyIFN5c3RlbXMxEjAQBgNVBAMMCUZ1c2lv"
  , "biBDQYIBATANBgkqhkiG9w0BAQUFAAOCAQEApAI7zfH6iiWulVB9f2bKmhNGgRte"
  , "9DRiWTLpP6lPyRBofEL4uC4EN2EkHZF/d2S9AFSiuWwcjECrss4dQEUMpChzojw1"
  , "hWrYHSqzpbsIOddvlkdpKSmShu1sl2/4a0o+9+WhzE0A5yb/w28AKd60EOdFmGUR"
  , "wckOh1Kjb10dkxkA/u/TMAfci4b86B+OH6MZ8Ecy0Ou6ET3yQxQjRM7XyyYRhGsy"
  , "WHmEGoWHAIQdlp+S8go8qK1sgoS0TBgaWLpDAhIdmL9DNHKNoD9x90K/VImO+Tfj"
  , "bX9SQTuI1LzqcpnxxAscO/QOjgH4VsAbYDvJUEIiSNJVTAvM7sPVurnlVg=="
  , "-----END CERTIFICATE-----"
  ]


backupScript :: Property NoInfo
backupScript =
  File.hasContent p
  [ "#!/bin/bash"
  , "set -o errexit -o nounset -o xtrace"
  , "name=${1?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "path=${2?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "bucket=${3?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "snapshot=\"${name}.$(date +%s%N)\""
  , "docker pull fusionapp/backup || true"
  , "btrfs subvolume snapshot -r ${path} /srv/duplicity/${snapshot}"
  , "chpst -L /srv/locks/${name}-maintenance.lock \\"
  , "  docker run --rm --volume=/srv/duplicity:/duplicity fusionapp/backup \\"
  , "  --no-encryption --allow-source-mismatch --no-print-statistics --verbosity error \\"
  , "  --name ${name} --full-if-older-than 2W --exclude /duplicity/${snapshot}/dumps --exclude /duplicity/${snapshot}/\\*.axiom/run/logs \\"
  , "  /duplicity/${snapshot} ${bucket}"
  , "btrfs subvolume delete /srv/duplicity/${snapshot}"
  ] `onChange` (File.mode p (combineModes (ownerWriteMode:readModes ++ executeModes)))
  where p = "/usr/local/bin/fusion-backup"


globalCerts :: Property HasInfo
globalCerts = propertyList "Certificates installed globally" $ props
              & File.dirExists "/srv/certs"
              & File.hasContent "/srv/certs/dhparam.pem" dhparam2048
              & File.dirExists "/srv/certs/public"
              & File.hasContent "/srv/certs/public/fusion-ca.crt.pem" fusionCa


simpleRelay :: Property NoInfo
simpleRelay =
  "/etc/ssmtp/ssmtp.conf" `File.hasContent`
  [ "Root=dev@fusionapp.com"
  , "Mailhub=smtp.fusionapp.com:587"
  , "RewriteDomain=fusionapp.com"
  , "FromLineOverride=yes"
  ] `requires` Apt.installed ["ssmtp"]


standardSystem :: HostName -> DebianSuite -> Architecture -> Host
standardSystem hn suite arch =
  host hn
  & os (System (Debian suite) arch)
  -- Can't turn this on because 127.0.1.1 in /etc/hosts is a problem
  -- & Hostname.sane
  & Hostname.searchDomain
  & Apt.installed ["libnss-myhostname"]
  & standardNsSwitch
  & Apt.stdSourcesList
  & Apt.unattendedUpgrades
  & Apt.cacheCleaned
  & Apt.installed [ "openssh-server"
                  , "openssh-client"
                  , "git"
                  , "kexec-tools"
                  , "needrestart"
                  , "runit"
                  ]
  & "/etc/needrestart/conf.d/10-local-disabled.conf" `File.hasContent`
  [ "$nrconf{override_rc}{q(^docker)} = 0;"
  , "$nrconf{override_rc}{q(^systemd-nspawn)} = 0;"
  ]
  & Apt.serviceInstalledRunning "ntp"
  & simpleRelay
  & Systemd.installed
  & Systemd.persistentJournal
  & Cron.runPropellor (Cron.Times "30 * * * *")
  & Ssh.randomHostKeys
  & Ssh.permitRootLogin Ssh.WithoutPassword
  & Apt.installed ["sudo"]
  & propertyList "admin accounts" ([ User.accountFor
                                   , User.lockedPassword
                                   , Sudo.enabledFor
                                   , flip User.hasGroup (Group "systemd-journal")
                                   , flip User.hasGroup (Group "adm")
                                   ] <*> admins)
  & adminKeys (User "root")
  & tristanKeys (User "tristan")
  & jjKeys (User "jj")
  & darrenKeys (User "darren")
  & williamKeys (User "william")
  & Ssh.noPasswords
  & File.hasContent "/etc/sysctl.d/local-net.conf"
    [ "net.core.default_qdisc=fq"
    , "net.ipv4.tcp_ecn=1"
    ]
  & globalCerts
  -- Useful utilities
  & Apt.installed [ "ethtool"
                  , "htop"
                  , "less"
                  , "curl"
                  , "dstat"
                  , "vim-nox"
                  , "atool"
                  , "sqlite3"
                  , "fish"
                  , "rsync"
                  , "ncdu"
                  , "iftop"
                  ]


standardNsSwitch :: Property NoInfo
standardNsSwitch =
  File.hasContent "/etc/nsswitch.conf"
  [ "passwd:         compat mymachines"
  , "group:          compat mymachines"
  , "shadow:         compat"
  , ""
  , "hosts:          files dns mymachines myhostname"
  , "networks:       files"
  , ""
  , "protocols:      db files"
  , "services:       db files"
  , "ethers:         db files"
  , "rpc:            db files"
  , ""
  , "netgroup:       nis"
  ]


admins :: [User]
admins = map User ["tristan", "jj", "darren", "william"]


tristanKeys :: User -> Property NoInfo
tristanKeys user = propertyList "keys for tristan" $ map (Ssh.authorizedKey user)
                   [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTItuXoGILFK8Y7+y07e5pomUwNfsvptD/jiep8MA8ChcVYZMe/Pl++eBXPz71fjGUWR8H86chPYa5omMLaaJQ0KNjmqzyp27GKVxrSYxt3pkv34xkxkN0HYoGRR6a7JiV2vjOI7Av71lh6WOMA315I+y7vpIenLU/kWiy/YkRO6fe7Bh9ZbMCspmREupsnHH8Zxu13xakQFZ2OzxhbDjWDHG42zZnbR3KCEVAE5/IM+RREZfFGiqTlbCEe2pCRKAntk2CS9E9f360KxMerRJAoQtHzuF1EZ+A1rn2lNLm9KW7n99EyuUt5W1E0dnB0Au7uYs7tUyAKjIZIg9OrHjR cardno:000603011845"
                   , "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg4PwvtqWHhan0rGxKAQn+n1IIKJJ0JsTMFdZiTFeOj mithrandi@lorien"
                   ]


jjKeys :: User -> Property NoInfo
jjKeys user = propertyList "keys for jj" $ map (Ssh.authorizedKey user)
              [ "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtd+yaE7w3PDdM9MLyDlMa4QoUOHNLjva/CGZe+1v4u7oOXDe4d6RLSJd1fZf1De2qZhrgPzOf7yh8MSK1nSW/dZrlt+Fd6aHIPG05lnTEV6SqxkhwaadixqqVZjtVAv3NpSjXfOGitAcIltkwourQKvAmYWzMMyYe4iF21XPcaU39PQud5b84hChAnHRBjyA0TFOpu3qs+SVetRsmU4S9ii1B/XbS6ktxwXqcXjc8HCG0G53VoR8dCmqVpyk3k5rcvSHa2gctXyQGbOIeO8un+613KWc2dTB/xhRUhF3bgoo846e3wFyFu85W/RdCj32BXW2FQZvPIJyciuWbX0TBw== jonathan@Callisto.local"
              , "ssh-dss AAAAB3NzaC1kc3MAAACBAJxgWfVKcnIBUYs8ymiEbbHbX5SLyHeN20Vofhbrpw6h5XujNy1aChTDupJ7p/YZIP4jhgZmvhm33hosbM3P4r2SBKSQ2SK3q4HbGkwPdy5N+bPgtcuNUkCwgBU0EKvUjM7/i7zFq9BD40402OeAX5zz9bwZ39BhI3d2oQ64+2s9AAAAFQC8cxb2WSfUYczmaIS6dxcnjYsXRQAAAIBz28PfwuI4qLaf1LRu6YJLGPEvT8FBVfCDGBCWmlE1NnJG+DfUEFXsSElpra4k/5p9fYEPpf1WRCKSDYzR2T5zWfI/A2eAxviixOVhlghj8N26eqQF8WacZtD+zgm06QUHWRwUgw3OJXiFdLVlSI5/QG6MeR4kVc3xKIxG8V9KsAAAAIB6T3L2PIqbnK5NOzGPvMnzA5bgk2NelrXhssNZTGbYNnIXwNHzDVWCqAHwX6iwGN4+ra+XwqW0FPvN45CP5PMsCdZqLl7mtk7gtO5ig6hPNEQ4wWXW/IyYpdRTtcA//Hbvmf1rvzRCWUweyzoDoVtoGwo9jMztyHnJrrPOXWf9cw== JJ@Triton"
              ]


darrenKeys :: User -> Property NoInfo
darrenKeys user = propertyList "keys for darren" $ map (Ssh.authorizedKey user)
                  [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/KNDsEPU/5cJ4bKN4Vd6XRXJlI+m2d6iW+1VWHDWqkJ313+3/8RXndZHk3dhngVtNIBk2HxwrsiZocMXRh5+MouZfAlonMFHOXrD3f1MHSvjM9m1IDPIUhVT7qOao509MAYcKlpBroxNL8yYbg/7UE4Y+ML5VQHAkr+/4KoGYzqod5qkWjv15qqVFZKFovoFz0S+fSIEuEIH6gnJc76KPzDfXs3GJTN7icFFWyx9XW7bMv/QZMLjt1p7bHv8kbe6aZ0/lRyiTKTPAYePctuKtFMssU1QZzVlKCOCnc444HZVYERUdEJDKmXSOrVYFKBIK7IMfbwnIYm39L05W9JIX5jxhciE7/MSeW2HRpT9CtfglyTmwK9FVViGAR/Vz1lGXH7Jnaq8MiLJvfpVASbBTKq24KBrXo9a04AE6AnoCz43z7tk/H7Z4xWdUvt2bJ3brRS1hLtX5QEUVREiDDRCtzgtfvZrDab2lHTvVpagQeZwew9QikLw2uOFNOEaMbIDH3nQVG2l1JEBykogiiHyPRlMr2wfeHbJ6TSBjuQZl5EWrN3C5ajx0rNyv8VIHmHPqGO+Ym9HDls5wkCetsM2qxbnDobL46asOfrr/QXFaGwd+IqW1TeENrH3tfp+c2F20HP1cOCKMGk4q0gvqE9ybwhydTQlC9lvF6U3BZXZdIQ== potato@freyr"
                  , "ssh-dss AAAAB3NzaC1kc3MAAACBAPbbMpY6lrl3v5arAVaOESEfAr1kjQBquS6DXjgtA+5rnrIJ/mhZDE4nynfS9BHaJfsXe4hT9Dnzbt2UfiB5jcKxgRxS8L0iXStjfy6SfBe/jnJyYp/NPRUtMsmZebGrHk82L3xef10HwlBw6CQIoOoaWUUHgNKXm9L5JXGHpzrTAAAAFQDbY2/2rjLZ0E6/f5Y6gZEprdnGIQAAAIEA5iFM6upGNgorTyo+KmnRY0x6RQOTWzBVneyqFqEYgWx+F3l/LO89M7Zrao08QYY03i8JiKtdrRl1zkmiHIZ5MfhsESN8VD2OoRVU//YZcBTd3RBwPjaL4xaL70JdJz1xQppDfCAtXFC5bQlNVxfpdyHPrHuTnszptoLAZj4qMCwAAACAY664fkO6wJAKjSaNh+UjOGRUY/gdNRbKCSIrNK30cKkQpKzI/IxU64GYbprab5jUIGA8yyf1h5T+QAP/oPW+Xh/oYPQKQ1Z3lkCyaAEPrHwRgleI+No7KIBZMpLj9GwnNVO9d+iE3j+pCsLlm6dk4eY3jHDlwN+AX+RRhMlnIso= potato@vm"
                  , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCx+BiVfTdyZ4dDyethjL4PHltDB1jBJI65iKIzrg6DBkG/DJxNShCbrS/SsR9xkJVlUhyUxjdLQvdGTsbIxPphCuRivk71ccMj1/iN32PkoNIujSCa66rGL/NKO000Ir/ZWiBXG+p5svSZuojTfL+BEPsEfpLoLhBvt8M1TbhyCJl+bQ7wW0Djlp/tYcpSkmAg5fXXragf4Q6t8UrTjkigzDqi0SAttGylflPlQBo23ImJdEbduYQJdtOx8E7675bodSADqK03ouBXti1/1ZKYO6e1X8KMzvJZEmRTz7JcNFB7ICJJJWIYSW05uoJCTKk2ZACa8XyM+b3vXRvqXzVd darren@yk2"
                  , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoiVJFBthrh+YDlE7U5FNopTzDwQwtCLdASt3ex+UdVPzkLxiHtDaqQYwkGquTk8w6nKbIhTc9cuSe065EqPvpZznOFks07dW5vHUn+C+soZ18VXt7WOX8c8TlGVCMHQ00VFxAqyAltleWYTfpUUGHMcTijN1s/8CgF/p6VlLDzzM704cg4iI0xzN+x9JtKWs6i042RlevO8UA0t2oSYKM08IcKiC/Hi1yjRYFC6yB2lh3c/4BD7V+j4stLvmgk1aBYQHn+2O7VEhwKAgGG5pJUKU373GWDFBDB3ox+ACIgjWLEFMoJCsLlxObiiBMCj88BmVu7aAViqCdl//KHZ3N cardno:000603011904"
                  ]


williamKeys :: User -> Property NoInfo
williamKeys user = propertyList "keys for william" $ map (Ssh.authorizedKey user)
                   [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiy5Sx5pADzWP9Aq+ecagisuc2jZJaR/DV4PoVWxNAH4HngybzBBUtTL/9BsLcTn5OKNGqc1Kk916PENBPN3sqNQJj1u+OUyibAT8Em/sEfaDZ5ykh++E0/ycKYFs2chXR7fPhe+68hLAMNS3GlKvf5ErmScz3oyDEwR73b00LfABz3rpy7YuxoNiA/PgPv4+5oaULUxo0ysGx+mcoAvrXwQ5u3KHPOKNNzN9E3gF5AhML+qGF5i7T3dYcZ0OsqkEJ4gSRG8PPVmX2rKMI+Ldvh0LI0Xa9fgaEgtC5X38u+0WalEE5EhBv5LUZKRu+9bzkR71jl9kbI86ld/QLYf9Z js@mvp.gg"
                   ]


adminKeys :: User -> Property NoInfo
adminKeys user = propertyList "admin keys" . map ($ user) $
                 [ tristanKeys
                 , jjKeys
                 , darrenKeys
                 , williamKeys
                 ]


standardContainer :: Systemd.MachineName -> DebianSuite -> Architecture -> Systemd.Container
standardContainer name suite arch =
  Systemd.container name chroot
  & Apt.stdSourcesList `onChange` Apt.upgrade
  -- Need cron installed for unattended-upgrades to work
  & Apt.installed ["cron"]
  & Apt.removed ["exim4", "exim4-base", "exim4-config", "exim4-daemon-light"]
  `onChange` Apt.autoRemove
  & Apt.unattendedUpgrades
  & Apt.cacheCleaned
  where chroot = Chroot.debootstrapped system Debootstrap.MinBase
        system = System (Debian suite) arch


apacheSvn :: Systemd.Container
apacheSvn = Systemd.container "apache-svn" chroot
            & Systemd.bind "/srv/svn"
            & Systemd.containerCfg "network-veth"
            & Systemd.running Systemd.networkd
            & Systemd.running "apache2" `requires` Apt.installed ["apache2"]
            & Apache.modEnabled "dav_svn" `requires` Apt.installed ["libapache2-svn"]
            & Apache.siteDisabled "000-default"
            & Apache.listenPorts [Port 8100]
            & Apache.siteEnabled "svn.quotemaster.co.za"
            [ "<VirtualHost *:8100>"
            , "  ServerName svn.quotemaster.co.za;"
            , "  <Location /svn>"
            , "      DAV             svn"
            , "      SVNParentPath   /srv/svn"
            , "      AuthName        Subversion"
            , "      AuthType        Basic"
            , "      AuthUserFile    /srv/svn/dav_svn.passwd"
            , "      <LimitExcept GET PROPFIND OPTIONS REPORT>"
            , "          Require valid-user"
            , "      </LimitExcept>"
            , Apache.allowAll
            , "  </Location>"
            , "</VirtualHost>"
            ]
  where chroot = Chroot.debootstrapped system Debootstrap.MinBase
        system = System (Debian (Stable "jessie")) "amd64"


nginxPrimary :: Systemd.Container
nginxPrimary = standardContainer "nginx-primary" (Stable "jessie") "amd64"
               & Systemd.running Systemd.networkd
               & Systemd.running "nginx" `requires` Nginx.installed
               & Systemd.bind "/srv/certs"
               & Nginx.siteEnabled "svn.quotemaster.co.za"
               [ " server {"
               , "    listen              41.72.130.249:80;"
               , "    server_name         svn.quotemaster.co.za;"
               , "    access_log          /var/log/nginx/svn.quotemaster.co.za_access.log;"
               , "    client_max_body_size 200m;"
               , ""
               , "    location / {"
               , "        proxy_set_header Host $host;"
               , "        proxy_set_header X-Real-IP $remote_addr;"
               , "        proxy_set_header X-Forwarded-Proto http;"
               , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
               , "        proxy_pass       http://10.0.0.2:8100;"
               , "    }"
               , "}"
               , ""
               , "server {"
               , "    listen              41.72.130.249:443 ssl;"
               , "    server_name         svn.fusionapp.com;"
               , "    ssl_certificate     /srv/certs/private/star.fusionapp.com.pem;"
               , "    ssl_certificate_key /srv/certs/private/star.fusionapp.com.pem;"
               , "    ssl_ciphers         ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AES:RSA+3DES:!ADH:!AECDH:!MD5;"
               , "    ssl_prefer_server_ciphers on;"
               , "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;"
               , "    ssl_dhparam         /srv/certs/dhparam.pem;"
               , "    ssl_session_cache   shared:SSL:50m;"
               , "    ssl_session_timeout 5m;"
               , "    access_log          /var/log/nginx/svn.fusionapp.com_tls_access.log;"
               , "    client_max_body_size 200m;"
               , ""
               , "    location / {"
               , "        proxy_set_header Host $host;"
               , "        proxy_set_header X-Real-IP $remote_addr;"
               , "        proxy_set_header X-Forwarded-Proto http;"
               , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
               , "        proxy_pass       http://10.0.0.2:8100;"
               , "    }"
               , "}"
               ]


mailRelayContainer :: Systemd.Container
mailRelayContainer = standardContainer "mail-relay" (Stable "jessie") "amd64"
                     & Systemd.running Systemd.networkd
                     & mailRelay


mailRelay :: Property HasInfo
mailRelay =
  propertyList "fusionapp.com mail relay" $ props
  & Systemd.running Systemd.networkd
  & Systemd.running "postfix" `requires` Postfix.installed
  & "/etc/aliases" `File.hasContent`
  [ "postmaster: root"
  , "root: dev@fusionapp.com"
  ] `onChange` Postfix.newaliases
  & Postfix.mainCfFile `File.containsLines`
  [ "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 41.72.130.248/29 41.72.129.157/32 129.232.129.136/29 197.189.229.120/29 41.72.135.80/29"
  ]
  `onChange` Postfix.dedupMainCf
  `onChange` Postfix.reloaded
  `describe` "postfix configured"
  & Postfix.mappedFile "/etc/postfix/master.cf"
  (flip File.containsLines
   [ "submission inet n - - - - smtpd"
   ])
  `describe` "postfix master.cf configured"
  `onChange` Postfix.reloaded


dhparam2048 :: [String]
dhparam2048 =
  [ "-----BEGIN DH PARAMETERS-----"
  , "MIIBCAKCAQEAxDV+dxRNpt4NL5EfIq9XpCd25rABEgjgA1oRdAs5CXl9Kd+DADmR"
  , "Hg74z1qVnN9z3u+IsPB26xR9tT6RjihCRhPL8ONcs/+1s0KpSiVd8qYzMz7NyYDk"
  , "EIxOdtf1555DKPJvKKkGkua5r9a5XkFhB/+ozH7AkqRdyj20PjsYtvFHbtePsslG"
  , "B0sQPB1iXyYyrZQ2TKP9Sqpe6AwqpxODBUwl+h4azXrtmzkQ6smj0BPKMg+g/GGp"
  , "aWglEnO4tQofYz48zRvHDtLNkcTfVhZ/Lwz+NZwyQ3uPlXmDppIyn8xwrkwq/6XN"
  , "6YHa2mdiITbsIILkNoRGtUSwFsKbyQaUcwIBAg=="
  , "-----END DH PARAMETERS-----"
  ]
