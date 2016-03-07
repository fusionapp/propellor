-- This is the main configuration file for Propellor, and is used to build
-- the propellor program.

import           Control.Applicative ((<$>), (<*>))
import           Propellor
import qualified Propellor.Property.Apache as Apache
import qualified Propellor.Property.Apt as Apt
import qualified Propellor.Property.Chroot as Chroot
import qualified Propellor.Property.Cron as Cron
import qualified Propellor.Property.Debootstrap as Debootstrap
import qualified Propellor.Property.File as File
import qualified Propellor.Property.Git as Git
import qualified Propellor.Property.Hostname as Hostname
import qualified Propellor.Property.Locale as Locale
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
          & droneKeys
          -- Local private certificates
          & File.dirExists "/srv/certs/private"
          & File.hasPrivContent "/srv/certs/private/fusiontest.net-fusionca.crt.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/scarlet.fusionapp.com.pem" hostContext
          & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/ca.crt" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/public/fusion-ca.crt.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & Cron.niceJob "fusion-backup" (Cron.Times "23 * * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-eu-uat.fusionapp.com"
          & File.dirExists "/srv/drone"
          & File.hasPrivContent "/srv/drone/dronerc" (Context "fusion builds")


onyx :: Host
onyx = standardSystem "onyx.fusionapp.com" (Stable "jessie") "amd64"
       & ipv4 "41.72.130.249"
       & fusionHost
       & Ssh.userKeys (User "root") hostContext
       [ (SshEd25519, pubKeyEd25519)
       , (SshEcdsa, pubKeyEcdsa)
       ]
       & Ssh.authorizedKey (User "root") pubKeyEd25519
       & Ssh.authorizedKey (User "root") pubKeyEcdsa
       -- Local private certificates
       & File.dirExists "/srv/certs/private"
       & File.hasPrivContent "/srv/certs/private/star.fusionapp.com.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/onyx.fusionapp.com.pem" hostContext
       & File.hasPrivContent "/srv/certs/private/prod.fusionapp.com.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/fusiontest.net.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/quotemaster.co.za.pem" (Context "fusion production")
       & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/ca.crt" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/public/fusion-ca.crt.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       & Systemd.nspawned nginxPrimary
       & Systemd.nspawned apacheSvn `requires` Systemd.running Systemd.networkd
       & Systemd.nspawned mailRelayContainer
       & Cron.niceJob "fusion-index-backup" (Cron.Times "41 1 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-index /srv/db/fusion-index s3://s3-eu-west-1.amazonaws.com/backups-fusion-index.fusionapp.com"
       & Cron.niceJob "fusion-prod backup" (Cron.Times "17 0-23/6 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-index /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-fusion-prod.fusionapp.com"
       & Cron.job "fusion-prod nightly deploy" (Cron.Times "7 1 * * *") (User "root") "/srv/fab" "git fetch && git reset --hard origin/master && git clean -dfx && fab fusion.deploy"
       where pubKeyEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdsS9oJKqICEvhJFHP4LQTjwso9QHSLTtjcBZR2r6kL root@onyx.fusionapp.com"
             pubKeyEcdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN3UsIwUsSCgItsJv6gdisBYfuxIwP5/jhfe+g1JD6NXqzgj7mUGjMO+tiatgNYauqaFB3JPoS2NsPo6t0jKbzs= root@onyx.fusionapp.com"


fusionHost :: Property HasInfo
fusionHost = propertyList "Platform dependencies for Fusion services" $ props
             & "/etc/timezone" `File.hasContent` ["Africa/Johannesburg"]
             & Apt.installed ["mercurial", "git"]
             & Apt.installed ["docker.io"]
             & propertyList "admin docker access"
             (flip User.hasGroup (Group "docker") <$> admins)
             & File.dirExists "/srv/duplicity"
             & File.hasPrivContent "/srv/duplicity/credentials.sh" hostContext
             & File.dirExists "/srv/locks"
             & Cron.niceJob "update fusion-fab" Cron.Daily (User "root") "/srv/fab" "/usr/bin/git fetch && /usr/bin/git reset --hard && /usr/bin/git clean -dfx"
             `requires` Git.cloned (User "root") "https://github.com/fusionapp/fusion-fab.git" "/srv/fab" Nothing
             & Apt.installed ["fabric"]
             & backupScript
             & restoreScript


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
  , "chpst -L \"/srv/locks/${name}-maintenance.lock\" \\"
  , "  docker run --rm --volume /srv/duplicity:/duplicity fusionapp/backup \\"
  , "  --no-encryption --allow-source-mismatch --no-print-statistics --verbosity error \\"
  , "  --name \"${name}\" --full-if-older-than 2W --exclude \"/duplicity/${snapshot}/dumps\" --exclude \"/duplicity/${snapshot}/*.axiom/run/logs\" \\"
  , "  \"/duplicity/${snapshot}\" \"${bucket}\""
  , "btrfs subvolume delete \"/srv/duplicity/${snapshot}\""
  ] `onChange` File.mode p (combineModes (ownerWriteMode:readModes ++ executeModes))
  where p = "/usr/local/bin/fusion-backup"


restoreScript :: Property NoInfo
restoreScript =
  File.hasContent p
  [ "#!/bin/bash"
  , "set -o errexit -o nounset -o xtrace"
  , "name=${1?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "path=${2?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "bucket=${3?\"Usage: $0 <name> <path> <S3 bucket>\"}"
  , "docker pull fusionapp/backup || true"
  , "chpst -L \"/srv/locks/${name}-maintenance.lock\" \\"
  , "  docker run --rm --volume /srv/duplicity:/duplicity \\"
  , "  --volume \"${path}\":\"${path}\" fusionapp/backup \\"
  , "  --no-encryption --no-print-statistics \\"
  , "  --name \"${name}\" \"${bucket}\" \"${path}\""
  ] `onChange` File.mode p (combineModes (ownerWriteMode:readModes ++ executeModes))
  where p = "/usr/local/bin/fusion-restore"


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
  -- Locales
  & Locale.available "en_ZA.UTF-8"
  & Locale.available "en_US.UTF-8"
  -- Base setup
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
  & "/etc/security/limits.d/10-local.conf" `File.hasContent`
  [ "* hard nofile 1000000"
  , "* soft nofile 1000000"
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
  & "en_ZA.UTF-8" `Locale.selectedFor` ["LANG"]
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
                   [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTItuXoGILFK8Y7+y07e5pomUwNfsvptD/jiep8MA8ChcVYZMe/Pl++eBXPz71fjGUWR8H86chPYa5omMLaaJQ0KNjmqzyp27GKVxrSYxt3pkv34xkxkN0HYoGRR6a7JiV2vjOI7Av71lh6WOMA315I+y7vpIenLU/kWiy/YkRO6fe7Bh9ZbMCspmREupsnHH8Zxu13xakQFZ2OzxhbDjWDHG42zZnbR3KCEVAE5/IM+RREZfFGiqTlbCEe2pCRKAntk2CS9E9f360KxMerRJAoQtHzuF1EZ+A1rn2lNLm9KW7n99EyuUt5W1E0dnB0Au7uYs7tUyAKjIZIg9OrHjR cardno000603011845"
                   , "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg4PwvtqWHhan0rGxKAQn+n1IIKJJ0JsTMFdZiTFeOj mithrandi@lorien"
                   ]


jjKeys :: User -> Property NoInfo
jjKeys user = propertyList "keys for jj" $ map (Ssh.authorizedKey user)
              [ "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtd+yaE7w3PDdM9MLyDlMa4QoUOHNLjva/CGZe+1v4u7oOXDe4d6RLSJd1fZf1De2qZhrgPzOf7yh8MSK1nSW/dZrlt+Fd6aHIPG05lnTEV6SqxkhwaadixqqVZjtVAv3NpSjXfOGitAcIltkwourQKvAmYWzMMyYe4iF21XPcaU39PQud5b84hChAnHRBjyA0TFOpu3qs+SVetRsmU4S9ii1B/XbS6ktxwXqcXjc8HCG0G53VoR8dCmqVpyk3k5rcvSHa2gctXyQGbOIeO8un+613KWc2dTB/xhRUhF3bgoo846e3wFyFu85W/RdCj32BXW2FQZvPIJyciuWbX0TBw== jonathan@Callisto.local"
              , "ssh-dss AAAAB3NzaC1kc3MAAACBAJxgWfVKcnIBUYs8ymiEbbHbX5SLyHeN20Vofhbrpw6h5XujNy1aChTDupJ7p/YZIP4jhgZmvhm33hosbM3P4r2SBKSQ2SK3q4HbGkwPdy5N+bPgtcuNUkCwgBU0EKvUjM7/i7zFq9BD40402OeAX5zz9bwZ39BhI3d2oQ64+2s9AAAAFQC8cxb2WSfUYczmaIS6dxcnjYsXRQAAAIBz28PfwuI4qLaf1LRu6YJLGPEvT8FBVfCDGBCWmlE1NnJG+DfUEFXsSElpra4k/5p9fYEPpf1WRCKSDYzR2T5zWfI/A2eAxviixOVhlghj8N26eqQF8WacZtD+zgm06QUHWRwUgw3OJXiFdLVlSI5/QG6MeR4kVc3xKIxG8V9KsAAAAIB6T3L2PIqbnK5NOzGPvMnzA5bgk2NelrXhssNZTGbYNnIXwNHzDVWCqAHwX6iwGN4+ra+XwqW0FPvN45CP5PMsCdZqLl7mtk7gtO5ig6hPNEQ4wWXW/IyYpdRTtcA//Hbvmf1rvzRCWUweyzoDoVtoGwo9jMztyHnJrrPOXWf9cw== JJ@Triton"
              ]


darrenKeys :: User -> Property NoInfo
darrenKeys user = propertyList "keys for darren" $ map (Ssh.authorizedKey user)
                  [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQD0SNokEjxqHvWbdyHs2pkf7gTpL464wv2I4vmIzFIjmd+8G5OMZkDme1CrS7jhi33dGM99zMZF1TC6Wbi7DshL9jX8Q8A2VJBN8Tm8FH1bmVM1eV44biAzvFmV9J2xeiGX2cM1rJMYn9CSbYBhwoi32OhvWxEV7FsKI6sipZiHtP0ClxyNbd8foM/AEfrRIEmTQad+ep6OvKsdkTwcJoywvqtgF0giiCMYkuXAYZzAm5+0ZcgYhdQdLXf8cCoxWxjX7cpwx+3CGJPbWVejmAunOjSuTQ1sfl73OrtjZd7hDdhtvQXhmJaJc8+bqoODUP94mS6zIKv8e09kY/ijcMRpHMC6ERtf3bB5qc+yWFGVwcIzwvta3IZ1nbmbea3gMv1yGXc5Qf4KSqrQvghZ7N/8Ava36njj3Zab6DqYNtnpdIeGUK5mGApE7PSHiVQWYtK11IPaYrnhiAQlN2V91G1J3hu6DkuO6d+ZdfzBEEfcCosW1MWdUyzX2X+34YOyFNEDVGy6gOk26Y9W57yPwH0FRmcOqNfWVqFGQuwrNY3m9J6XjJuhmhwTOeLUjePo68NDeEoabQ4IfPdMX5G3+mI6DgbwhOKlWLI8Lj35n8n0m0HwkIn6pm1Fov8eboE8oAzMoAoJH7Xb9zAgJxf2m+f1X/Dsks4Vv9X+rJza4xDCqQ== potato@potatop"
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


droneKeys :: Property NoInfo
droneKeys = propertyList "drone.io CI deployment keys"
  . map (Ssh.authorizedKey (User "root")) $
  [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4NcWgAGV+mmTQgMS56MmZBWs6wQzBDh5q36pE+iCztI+tzTSPAPd6yoZthDtk1OkHfNAqfSEnxhYneKF1a893jPhNCwJ1BgIYmuVUvX4NPy0A62iI3xaNKx9fXrW679TIYm21pkmkNs2O81P7oUl+wfuo5j33GRdNQxZKas8uJZ/HE09h+Vd4OH6GsjklBWJTSliidrzOWNyv7XvzUIBMOey6dfZOVMraKxTux0xhb28ITklMWLxZwJJzK9uzUlbZJa2P5lO3e30+IWbMZnFiRQqrPwofjsWxR7OUk4qn/KE4MejsNVo6YrnHGj9VKZQMWBJNS8aARq+zq8A8Fre1 fusionapp-diamond@drone"
  , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaL+2DoGktW0DRLBpLdJm4icbotFQwHMwRmyTQc+XTXmpq0w3FiO2xE2Vr0wDlaFKWfMsscVDbmfK6ViihVUOPSlG2rjaEnSHVRdw68yvl5uEA84Xtqu7D/lnjgOwHZT9wC3mCi2e0LpVvQSU4g27e0SSb+EyxTd7JrvVjJpR7+ycAqx0xnC0jHvjTDO1n5nDqiAicStk6W/BmXARIb0YoeKyowqTpyl2brmzjnmuDy28cmLSZXbshHUxaL1C2ZmJh6oVbBPQmBhZ4SsrGP4CgY66EVt3SlCQ4IE6dL+kOklRrxcnDGCh8uNKXs/dkZyT5Um0q6xhsy/JnDjQ+ruo7 fusionapp-fusion@drone"
  ]


standardContainer :: Systemd.MachineName -> DebianSuite -> Architecture -> Systemd.Container
standardContainer name suite arch =
  Systemd.container name system chroot
  & "/etc/security/limits.d/10-local.conf" `File.hasContent`
  [ "* hard nofile 1000000"
  , "* soft nofile 1000000"
  ]
  & Apt.stdSourcesList `onChange` Apt.upgrade
  -- Need cron installed for unattended-upgrades to work
  & Apt.installed ["cron"]
  & Apt.removed ["exim4", "exim4-base", "exim4-config", "exim4-daemon-light"]
  `onChange` Apt.autoRemove
  & Apt.unattendedUpgrades
  & Apt.cacheCleaned
  where chroot = Chroot.debootstrapped Debootstrap.MinBase
        system = System (Debian suite) arch


apacheSvn :: Systemd.Container
apacheSvn = Systemd.container "apache-svn" system chroot
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
  where chroot = Chroot.debootstrapped Debootstrap.MinBase
        system = System (Debian (Stable "jessie")) "amd64"


nginxPrimary :: Systemd.Container
nginxPrimary =
  standardContainer "nginx-primary" (Stable "jessie") "amd64"
  & Systemd.running Systemd.networkd
  & File.dirExists "/etc/systemd/system/nginx.service.d"
  & "/etc/systemd/system/nginx.service.d/limits.conf" `File.hasContent`
  [ "[Service]"
  , "LimitNOFILE=100000"
  ]
  & Systemd.running "nginx" `requires` Nginx.installed
  & Systemd.bind "/srv/certs"
  & Git.cloned (User "root") "https://github.com/fusionapp/fusion-error.git" "/srv/nginx/fusion-error" Nothing
  & File.dirExists "/srv/nginx/cache"
  & File.ownerGroup "/srv/nginx/cache" (User "www-data") (Group "www-data")
  & svnSite
  & andersonSite
  & entropySite
  & fusionSites
  & quotemasterSite
  & saxumSite


svnSite :: RevertableProperty NoInfo
svnSite =
  Nginx.siteEnabled "svn.quotemaster.co.za"
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


andersonSite :: RevertableProperty NoInfo
andersonSite =
  Nginx.siteEnabled "andersonquotes.co.za"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    server_name         andersonquotes.co.za www.andersonquotes.co.za;"
  , "    access_log          /var/log/nginx/anderson.access.log;"
  , ""
  , "    location / {"
  , "        proxy_read_timeout 5m;"
  , "        proxy_set_header Host quotemaster.co.za;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto http;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://41.72.129.157/anderson/;"
  , "    }"
  , "}"
  ]


entropySite :: RevertableProperty NoInfo
entropySite =
  Nginx.siteEnabled "entropy.fusionapp.com"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    server_name         entropy.fusionapp.com entropy.fusiontest.net bz-entropy.fusionapp.com;"
  , "    access_log          /var/log/nginx/entropy.access.log;"
  , "    gzip                off;"
  , ""
  , "    location / {"
  , "        client_max_body_size    512m;"
  , "        proxy_pass              http://onyx.fusionapp.com:8000;"
  , "        proxy_set_header        Host            $host;"
  , "        proxy_set_header        X-Real-IP       $remote_addr;"
  , "        proxy_read_timeout      60;"
  , "        proxy_buffering         off;"
  , "    }"
  , ""
  , "    location /new {"
  , "        client_max_body_size    512m;"
  , "        proxy_pass              http://onyx.fusionapp.com:8000;"
  , "        proxy_set_header        Host            $host;"
  , "        proxy_set_header        X-Real-IP       $remote_addr;"
  , "        proxy_read_timeout      60;"
  , "        proxy_buffering         off;"
  , "        allow 41.72.130.248/29;"
  , "        allow 41.72.135.84;"
  , "        allow 172.17.0.0/16;"
  , "        allow 192.168.50.10;"
  , "        allow 197.189.229.122;"
  , "        allow 52.31.216.9;"
  , "        deny all;"
  , "    }"
  , "}"
  ]


fusionSites :: Property HasInfo
fusionSites =
  propertyList "Fusion sites" $ props
  ! Nginx.siteEnabled "fusion-prod" []
  ! Nginx.siteEnabled "fusion-prod-tls" []
  & Nginx.siteEnabled "fusion-prod-bz"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    server_name         bz-ext.fusionapp.com bz.fusionapp.com prod.fusionapp.com absa-temp.fusionapp.com emerald.fusionapp.com af.fusionapp.com bn.fusionapp.com ud.fusionapp.com bi.fusionapp.com;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}.access.log;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript application/javascript text/css text/csv text/tab-separated-values;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    # Insane hack to force gzip compression for VMISFBUSTMG proxy. See also"
  , "    # the conditional proxy_pass blocks below."
  , "    set $proxy_encoding     identity;"
  , "    set $addr_and_encoding  \"${remote_addr}+${http_accept_encoding}\";"
  , "    if ($addr_and_encoding = \"196.23.144.84+\") {"
  , "        set $proxy_encoding gzip;"
  , "    }"
  , "    if ($addr_and_encoding = \"196.38.42.98+\") {"
  , "        set $proxy_encoding gzip;"
  , "    }"
  , "    proxy_set_header Accept-Encoding $proxy_encoding;"
  , ""
  , "    add_header \"X-UA-Compatible\" \"IE=edge\";"
  , ""
  , "    location /fusion-error {"
  , "        root            /srv/nginx;"
  , "    }"
  , ""
  , "    error_page  502     /fusion-error/502.html;"
  , "    error_page  504     /fusion-error/504.html;"
  , ""
  , "    location /__jsmodule__/ {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , ""
  , "        root            /srv/nginx/cache;"
  , "        expires         max;"
  , "        default_type    application/javascript;"
  , "        gzip_types      text/javascript application/javascript application/octet-stream text/plain;"
  , "        error_page      404 = @fetch;"
  , "        log_not_found   off;"
  , "    }"
  , ""
  , "    location @fetch {"
  , "        internal;"
  , "        proxy_pass              http://bz-int.fusionapp.com;"
  , "        proxy_store             on;"
  , "        proxy_store_access      user:rw  group:rw  all:r;"
  , "        proxy_temp_path         /srv/nginx/tmp;"
  , "        proxy_set_header        Accept-Encoding  \"\";"
  , "        root                    /srv/nginx/cache;"
  , "    }"
  , ""
  , "    location /static {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        expires                 30m;"
  , "        proxy_pass              http://onyx.fusionapp.com:8001;"
  , "    }"
  , ""
  , "    location /Fusion/documents {"
  , "        expires                 max;"
  , "        proxy_pass              http://onyx.fusionapp.com:8001;"
  , "    }"
  , ""
  , "    location / {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        proxy_pass              http://onyx.fusionapp.com:8001;"
  , "    }"
  , "}"
  ]
  & Nginx.siteEnabled "fusion-prod-bz-tls"
  [ "server {"
  , "    listen              41.72.130.253:443 default ssl;"
  , "    server_name         bz-ext.fusionapp.com bz.fusionapp.com prod.fusionapp.com absa-temp.fusionapp.com emerald.fusionapp.com af.fusionapp.com bn.fusionapp.com ud.fusionapp.com bi.fusionapp.com;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}_tls.access.log;"
  , "    ssl_certificate     /srv/certs/private/star.fusionapp.com.pem;"
  , "    ssl_certificate_key /srv/certs/private/star.fusionapp.com.pem;"
  , "    ssl_ciphers         ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH;"
  , "    ssl_prefer_server_ciphers on;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript application/javascript text/css text/csv text/tab-separated-values;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    location /fusion-endpoints {"
  , "        proxy_pass          http://onyx.fusionapp.com:8001/fusion-endpoints;"
  , "    }"
  , "}"
  ]
  & Nginx.siteEnabled "fusion-uat"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    server_name         fusiontest.net absa-temp.fusiontest.net t0.fusiontest.net t1.fusiontest.net tc.fusiontest.net td.fusiontest.net te.fusiontest.net tf.fusiontest.net;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}.access.log;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript text/css text/csv text/tab-separated-values;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    # Insane hack to force gzip compression for VMISFBUSTMG proxy. See also"
  , "    # the conditional proxy_pass blocks below."
  , "    set $proxy_encoding     identity;"
  , "    set $addr_and_encoding  \"${remote_addr}+${http_accept_encoding}\";"
  , "    if ($addr_and_encoding = \"196.23.144.84+\") {"
  , "        set $proxy_encoding gzip;"
  , "    }"
  , "    proxy_set_header Accept-Encoding $proxy_encoding;"
  , ""
  , "    location /fusion-error {"
  , "        root            /srv/nginx;"
  , "    }"
  , ""
  , "    error_page  502     /fusion-error/502.html;"
  , "    error_page  504     /fusion-error/504.html;"
  , ""
  , "    location /__jsmodule__/ {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        root            /srv/nginx/cache;"
  , "        expires         max;"
  , "        default_type    text/javascript;"
  , "        gzip_types      text/javascript application/octet-stream text/plain;"
  , "        error_page      404 = @fetch;"
  , "        log_not_found   off;"
  , "    }"
  , ""
  , "    location /static {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        expires         30m;"
  , "        proxy_pass      http://scarlet.fusionapp.com;"
  , "    }"
  , ""
  , "    location @fetch {"
  , "        internal;"
  , "        proxy_pass              http://scarlet.fusionapp.com;"
  , "        proxy_buffering         on;"
  , "        proxy_store             on;"
  , "        proxy_store_access      user:rw  group:rw  all:r;"
  , "        proxy_temp_path         /srv/nginx/tmp;"
  , "        root                    /srv/nginx/cache;"
  , "    }"
  , ""
  , "    location /Fusion/documents {"
  , "        expires                 max;"
  , "        proxy_pass              http://scarlet.fusionapp.com;"
  , "    }"
  , ""
  , "    location = / {"
  , "        rewrite ^ $scheme://$host/private/ redirect;"
  , "    }"
  , ""
  , "    location / {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        proxy_pass              http://scarlet.fusionapp.com;"
  , "    }"
  , "}"
  ]
  & Nginx.siteEnabled "fusion-uat-tls"
  [ "server {"
  , "    listen              41.72.130.253:443;"
  , "    server_name         fusiontest.net;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}_tls.access.log;"
  , "    ssl                 on;"
  , "    ssl_certificate     /srv/certs/private/fusiontest.net.pem;"
  , "    ssl_certificate_key /srv/certs/private/fusiontest.net.pem;"
  , "    ssl_ciphers         ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH;"
  , "    ssl_prefer_server_ciphers on;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript text/css text/csv text/tab-separated-values;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_read_timeout  600;"
  , "    client_max_body_size 512m;"
  , ""
  , "    location /fusion-endpoints {"
  , "        proxy_pass          http://scarlet.fusionapp.com/fusion-endpoints;"
  , "    }"
  , "}"
  ]


quotemasterSite :: RevertableProperty NoInfo
quotemasterSite =
  Nginx.siteEnabled "quotemaster"
  [ "server {"
  , "    listen              41.72.131.181:80;"
  , "    server_name         quotemaster.co.za www.quotemaster.co.za;"
  , "    access_log          /var/log/nginx/quotemaster.co.za.access.log;"
  , "    location / {"
  , "        rewrite ^(.*)$ https://quotemaster.co.za$1 permanent;"
  , "    }"
  , "}"
  , ""
  , "server {"
  , "    listen              41.72.131.181:443 default ssl;"
  , "    server_name         quotemaster.co.za;"
  , "    ssl_certificate     /srv/certs/private/quotemaster.co.za.pem;"
  , "    ssl_certificate_key /srv/certs/private/quotemaster.co.za.pem;"
  , "    ssl_ciphers         ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AES:RSA+3DES:!ADH:!AECDH:!MD5;"
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;"
  , "    ssl_session_cache   shared:SSL:50m;"
  , "    ssl_session_timeout 5m;"
  , "    access_log          /var/log/nginx/quotemaster.co.za_tls.access.log;"
  , "    location / {"
  , "        add_header Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\";"
  , "        add_header X-Frame-Options SAMEORIGIN;"
  , "        proxy_read_timeout 10m;"
  , "        proxy_set_header Host $host;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto https;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://41.72.129.157;"
  , "    }"
  , "}"
  ]


saxumSite :: RevertableProperty NoInfo
saxumSite =
  Nginx.siteEnabled "saxumretail.com"
  [ "server {"
  , "    listen              41.72.131.181:80;"
  , "    server_name         www.saxumretail.com;"
  , "    access_log          /var/log/nginx/saxumretail.access.log;"
  , "    location / {"
  , "        proxy_read_timeout 5m;"
  , "        proxy_set_header Host quotemaster.co.za;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto http;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://41.72.129.157/quickquote/;"
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
  [ "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 41.72.130.248/29 41.72.129.157/32 129.232.129.136/29 197.189.229.120/29 41.72.135.80/29 172.17.0.0/16"
  ]
  `onChange` Postfix.dedupMainCf
  `onChange` Postfix.reloaded
  `describe` "postfix configured"
  & Postfix.mappedFile "/etc/postfix/master.cf"
  (`File.containsLines`
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
