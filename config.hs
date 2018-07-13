{-# LANGUAGE TemplateHaskell #-}

import           Control.Applicative ((<$>), (<*>))
import           Propellor
import qualified Propellor.Property.Apt as Apt
import           Propellor.Property.Bootstrap
import qualified Propellor.Property.Cron as Cron
import qualified Propellor.Property.File as File
import qualified Propellor.Property.Git as Git
import qualified Propellor.Property.Hostname as Hostname
import qualified Propellor.Property.LetsEncrypt as LetsEncrypt
import qualified Propellor.Property.Locale as Locale
import qualified Propellor.Property.Nginx as Nginx
import qualified Propellor.Property.Ssh as Ssh
import qualified Propellor.Property.Sudo as Sudo
import qualified Propellor.Property.Systemd as Systemd
import qualified Propellor.Property.User as User
import           System.Posix.Files
import           Utility.Embed
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
scarlet = host "scarlet.fusionapp.com" $ props
          & standardSystem (Stable "stretch") X86_64
          & ipv4 "197.189.229.122"
          & hetznerResolv
          & fusionHost
          -- Local private certificates
          & File.dirExists "/srv/certs/private"
          & File.hasPrivContent "/srv/certs/private/fusiontest.net-fusionca.crt.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/scarlet.fusionapp.com.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/mfc-fusion-uat.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/mfc-fusion-jwt-uat.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/ariva.pem" (Context "fusion production")
          & File.hasPrivContent "/srv/certs/private/absa-datapower-uat.pem" hostContext
          & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & Cron.niceJob "fusion-backup" (Cron.Times "23 3 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-eu-uat.fusionapp.com"
          & caddyfile
          & File.dirExists "/srv/catcher-in-the-rye"
          & File.hasPrivContent "/srv/catcher-in-the-rye/config.yaml" (Context "fusion aux")
          & prometheusConfig
          & File.dirExists "/srv/drone-scheduler"
          & File.hasContent "/srv/drone-scheduler/schedules.yaml" $(sourceFile "files/drone-schedules.yaml")


onyx :: Host
onyx = host "onyx.fusionapp.com" $ props
       & standardSystem (Stable "stretch") X86_64
       & ipv4 "41.72.130.253"
       & hetznerResolv
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
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-jwt-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/fusiontest.net.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/ariva.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/absa-datapower-prod.pem" (Context "fusion production")
       & File.notPresent "/srv/certs/private/quotemaster.co.za.pem"
       & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       -- Work around Propellor issue, not sure exactly what is wrong here.
       & Apt.installed ["debootstrap"]
       & Apt.installed ["systemd-container"]
       & Systemd.running Systemd.networkd
       & Systemd.nspawned nginxPrimary
       & Cron.job "fusion-index-backup" (Cron.Times "41 1 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-index /srv/db/fusion-index s3://s3-eu-west-1.amazonaws.com/backups-fusion-index.fusionapp.com"
       & Cron.job "fusion-prod backup" (Cron.Times "17 0-23/4 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-prod /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-fusion-prod.fusionapp.com"
       & Cron.job "weekly btrfs balance" (Cron.Times "18 3 * * Sun") (User "root") "/tmp" "/bin/btrfs balance start -v -dusage=50 -musage=50 /"
       & fusionDumpsCleaned
       & prometheusProdConfig
       where pubKeyEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdsS9oJKqICEvhJFHP4LQTjwso9QHSLTtjcBZR2r6kL root@onyx.fusionapp.com"
             pubKeyEcdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN3UsIwUsSCgItsJv6gdisBYfuxIwP5/jhfe+g1JD6NXqzgj7mUGjMO+tiatgNYauqaFB3JPoS2NsPo6t0jKbzs= root@onyx.fusionapp.com"


fusionHost :: Property (HasInfo + DebianLike)
fusionHost = propertyList "Platform dependencies for Fusion services" $ props
             & "/etc/timezone" `File.hasContent` ["Africa/Johannesburg"]
             & Apt.installed ["mercurial", "git"]
             -- Upgraded Docker
             & Apt.installed ["docker-ce"]
             `requires` Apt.setSourcesListD ["deb [arch=amd64] https://download.docker.com/linux/debian stretch stable"] "docker"
             `requires` Apt.installed ["apt-transport-https"]
             `requires` Apt.trustsKey dockerKey
             `requires` dockerOptions
             & propertyList "admin docker access"
             (toProps (flip User.hasGroup (Group "docker") <$> admins))
             & File.dirExists "/srv/duplicity"
             & File.hasPrivContent "/srv/duplicity/credentials.sh" hostContext
             & File.dirExists "/srv/locks"
             & backupScript
             & restoreScript
             & droneKeys
             & duplicityLocksCleaned


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


dockerKey :: Apt.AptKey
dockerKey =
  Apt.AptKey "docker" $ unlines
  [ "-----BEGIN PGP PUBLIC KEY BLOCK-----"
  , ""
  , "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"
  , "YT90qFF93M3v01BbxP+EIY2/9tiIPbrd"
  , "=0YYh"
  , "-----END PGP PUBLIC KEY BLOCK-----"
  ]


dockerOptions :: Property UnixLike
dockerOptions = propertyList "Docker options" $ props
  & File.dirExists "/etc/systemd/system/docker.service.d"
  & File.hasContent "/etc/systemd/system/docker.service.d/options.conf"
  [ "[Service]"
  , "ExecStart="
  , unwords
    [ "ExecStart=/usr/bin/dockerd -H fd://"
    , "--log-driver=json-file"
    , "--log-opt max-size=10m"
    , "--log-opt max-file=5"
    ]
  ]


backupScript :: Property UnixLike
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


restoreScript :: Property UnixLike
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


globalCerts :: Property UnixLike
globalCerts = propertyList "Certificates installed globally" $ props
              & File.dirExists "/srv/certs"
              & File.hasContent "/srv/certs/dhparam.pem" $(sourceFile "files/dhparam.pem")
              & File.dirExists "/srv/certs/public"
              & File.hasContent "/srv/certs/public/fusion-ca.crt.pem" fusionCa


hetznerResolv :: Property UnixLike
hetznerResolv =
  "/etc/resolv.conf" `File.hasContent`
  [ "search fusionapp.com"
  , "domain fusionapp.com"
  , "nameserver 41.203.18.183"
  , "nameserver 196.22.142.222"
  , "nameserver 41.204.202.244"
  , "nameserver 197.221.0.5"
  ]


standardSystem :: DebianSuite -> Architecture -> Property (HasInfo + Debian)
standardSystem suite arch =
  propertyList "standard system" $ props
  & osDebian suite arch
  & bootstrapWith (Robustly Stack)
  -- Can't turn this on because 127.0.1.1 in /etc/hosts is a problem
  -- & Hostname.sane
  & Hostname.searchDomain
  -- Locales
  & Locale.available "en_ZA.UTF-8"
  & Locale.available "en_US.UTF-8"
  -- Base setup
  & Apt.installed ["libnss-myhostname"]
  & standardNsSwitch
  & Apt.stdSourcesList `onChange` Apt.upgrade
  & Apt.unattendedUpgrades
  & Apt.cacheCleaned
  & Apt.installed [ "openssh-server"
                  , "openssh-client"
                  , "git"
                  , "kexec-tools"
                  , "needrestart"
                  , "runit"
                  , "intel-microcode"
                  , "mcelog"
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
  & Ssh.setSshdConfigBool "UseDNS" False
  & Apt.installed ["sudo"]
  & propertyList "admin accounts"
  (toProps $
   [ User.accountFor
   , User.lockedPassword
   , setupRevertableProperty . Sudo.enabledFor
   , flip User.hasGroup (Group "systemd-journal")
   , flip User.hasGroup (Group "adm")
   ] <*> admins)
  & adminKeys (User "root")
  & tristanKeys (User "tristan")
  & jjKeys (User "jj")
  & darrenKeys (User "darren")
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
  where simpleRelay =
          "/etc/ssmtp/ssmtp.conf"
          `File.hasPrivContent` anyContext
          `requires` Apt.installed ["ssmtp"]


standardNsSwitch :: Property UnixLike
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
admins = map User ["tristan", "jj", "darren"]


tristanKeys :: User -> Property UnixLike
tristanKeys user = propertyList "keys for tristan"
                   . toProps
                   . map (setupRevertableProperty . Ssh.authorizedKey user) $
                   [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTItuXoGILFK8Y7+y07e5pomUwNfsvptD/jiep8MA8ChcVYZMe/Pl++eBXPz71fjGUWR8H86chPYa5omMLaaJQ0KNjmqzyp27GKVxrSYxt3pkv34xkxkN0HYoGRR6a7JiV2vjOI7Av71lh6WOMA315I+y7vpIenLU/kWiy/YkRO6fe7Bh9ZbMCspmREupsnHH8Zxu13xakQFZ2OzxhbDjWDHG42zZnbR3KCEVAE5/IM+RREZfFGiqTlbCEe2pCRKAntk2CS9E9f360KxMerRJAoQtHzuF1EZ+A1rn2lNLm9KW7n99EyuUt5W1E0dnB0Au7uYs7tUyAKjIZIg9OrHjR cardno000603011845"
                   , "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg4PwvtqWHhan0rGxKAQn+n1IIKJJ0JsTMFdZiTFeOj mithrandi@lorien"
                   ]


jjKeys :: User -> Property UnixLike
jjKeys user = propertyList "keys for jj"
              . toProps
              . map (setupRevertableProperty . Ssh.authorizedKey user) $
              [ "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtd+yaE7w3PDdM9MLyDlMa4QoUOHNLjva/CGZe+1v4u7oOXDe4d6RLSJd1fZf1De2qZhrgPzOf7yh8MSK1nSW/dZrlt+Fd6aHIPG05lnTEV6SqxkhwaadixqqVZjtVAv3NpSjXfOGitAcIltkwourQKvAmYWzMMyYe4iF21XPcaU39PQud5b84hChAnHRBjyA0TFOpu3qs+SVetRsmU4S9ii1B/XbS6ktxwXqcXjc8HCG0G53VoR8dCmqVpyk3k5rcvSHa2gctXyQGbOIeO8un+613KWc2dTB/xhRUhF3bgoo846e3wFyFu85W/RdCj32BXW2FQZvPIJyciuWbX0TBw== jonathan@Callisto.local"
              , "ssh-dss AAAAB3NzaC1kc3MAAACBAJxgWfVKcnIBUYs8ymiEbbHbX5SLyHeN20Vofhbrpw6h5XujNy1aChTDupJ7p/YZIP4jhgZmvhm33hosbM3P4r2SBKSQ2SK3q4HbGkwPdy5N+bPgtcuNUkCwgBU0EKvUjM7/i7zFq9BD40402OeAX5zz9bwZ39BhI3d2oQ64+2s9AAAAFQC8cxb2WSfUYczmaIS6dxcnjYsXRQAAAIBz28PfwuI4qLaf1LRu6YJLGPEvT8FBVfCDGBCWmlE1NnJG+DfUEFXsSElpra4k/5p9fYEPpf1WRCKSDYzR2T5zWfI/A2eAxviixOVhlghj8N26eqQF8WacZtD+zgm06QUHWRwUgw3OJXiFdLVlSI5/QG6MeR4kVc3xKIxG8V9KsAAAAIB6T3L2PIqbnK5NOzGPvMnzA5bgk2NelrXhssNZTGbYNnIXwNHzDVWCqAHwX6iwGN4+ra+XwqW0FPvN45CP5PMsCdZqLl7mtk7gtO5ig6hPNEQ4wWXW/IyYpdRTtcA//Hbvmf1rvzRCWUweyzoDoVtoGwo9jMztyHnJrrPOXWf9cw== JJ@Triton"
              ]


darrenKeys :: User -> Property UnixLike
darrenKeys user = propertyList "keys for darren"
                  . toProps
                  . map (setupRevertableProperty . Ssh.authorizedKey user) $
                  [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQD0SNokEjxqHvWbdyHs2pkf7gTpL464wv2I4vmIzFIjmd+8G5OMZkDme1CrS7jhi33dGM99zMZF1TC6Wbi7DshL9jX8Q8A2VJBN8Tm8FH1bmVM1eV44biAzvFmV9J2xeiGX2cM1rJMYn9CSbYBhwoi32OhvWxEV7FsKI6sipZiHtP0ClxyNbd8foM/AEfrRIEmTQad+ep6OvKsdkTwcJoywvqtgF0giiCMYkuXAYZzAm5+0ZcgYhdQdLXf8cCoxWxjX7cpwx+3CGJPbWVejmAunOjSuTQ1sfl73OrtjZd7hDdhtvQXhmJaJc8+bqoODUP94mS6zIKv8e09kY/ijcMRpHMC6ERtf3bB5qc+yWFGVwcIzwvta3IZ1nbmbea3gMv1yGXc5Qf4KSqrQvghZ7N/8Ava36njj3Zab6DqYNtnpdIeGUK5mGApE7PSHiVQWYtK11IPaYrnhiAQlN2V91G1J3hu6DkuO6d+ZdfzBEEfcCosW1MWdUyzX2X+34YOyFNEDVGy6gOk26Y9W57yPwH0FRmcOqNfWVqFGQuwrNY3m9J6XjJuhmhwTOeLUjePo68NDeEoabQ4IfPdMX5G3+mI6DgbwhOKlWLI8Lj35n8n0m0HwkIn6pm1Fov8eboE8oAzMoAoJH7Xb9zAgJxf2m+f1X/Dsks4Vv9X+rJza4xDCqQ== potato@potatop"
                  , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCx+BiVfTdyZ4dDyethjL4PHltDB1jBJI65iKIzrg6DBkG/DJxNShCbrS/SsR9xkJVlUhyUxjdLQvdGTsbIxPphCuRivk71ccMj1/iN32PkoNIujSCa66rGL/NKO000Ir/ZWiBXG+p5svSZuojTfL+BEPsEfpLoLhBvt8M1TbhyCJl+bQ7wW0Djlp/tYcpSkmAg5fXXragf4Q6t8UrTjkigzDqi0SAttGylflPlQBo23ImJdEbduYQJdtOx8E7675bodSADqK03ouBXti1/1ZKYO6e1X8KMzvJZEmRTz7JcNFB7ICJJJWIYSW05uoJCTKk2ZACa8XyM+b3vXRvqXzVd darren@yk2"
                  ]


adminKeys :: User -> Property UnixLike
adminKeys user = propertyList "admin keys" . toProps . map ($ user) $
                 [ tristanKeys
                 , jjKeys
                 , darrenKeys
                 ]


droneKeys :: Property UnixLike
droneKeys = propertyList "drone.io CI deployment keys"
            . toProps
            . map (setupRevertableProperty . Ssh.authorizedKey (User "root")) $
            [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4NcWgAGV+mmTQgMS56MmZBWs6wQzBDh5q36pE+iCztI+tzTSPAPd6yoZthDtk1OkHfNAqfSEnxhYneKF1a893jPhNCwJ1BgIYmuVUvX4NPy0A62iI3xaNKx9fXrW679TIYm21pkmkNs2O81P7oUl+wfuo5j33GRdNQxZKas8uJZ/HE09h+Vd4OH6GsjklBWJTSliidrzOWNyv7XvzUIBMOey6dfZOVMraKxTux0xhb28ITklMWLxZwJJzK9uzUlbZJa2P5lO3e30+IWbMZnFiRQqrPwofjsWxR7OUk4qn/KE4MejsNVo6YrnHGj9VKZQMWBJNS8aARq+zq8A8Fre1 fusionapp-diamond@drone"
            , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaL+2DoGktW0DRLBpLdJm4icbotFQwHMwRmyTQc+XTXmpq0w3FiO2xE2Vr0wDlaFKWfMsscVDbmfK6ViihVUOPSlG2rjaEnSHVRdw68yvl5uEA84Xtqu7D/lnjgOwHZT9wC3mCi2e0LpVvQSU4g27e0SSb+EyxTd7JrvVjJpR7+ycAqx0xnC0jHvjTDO1n5nDqiAicStk6W/BmXARIb0YoeKyowqTpyl2brmzjnmuDy28cmLSZXbshHUxaL1C2ZmJh6oVbBPQmBhZ4SsrGP4CgY66EVt3SlCQ4IE6dL+kOklRrxcnDGCh8uNKXs/dkZyT5Um0q6xhsy/JnDjQ+ruo7 fusionapp-fusion@drone"
            , "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1lvZPseVOYjIKm8jrxpvI1CcOo7aSkkk61u6/LJMPfD2nJOalGzMdUHU7dLlZDLkY4adH9/YlHOleP1u2Jw38PjA6wkuaLVXcGwo7zrkU8ufGlsG/yZL1ZZNk/5ltaz34pZ5DFkQuCq7NUDTZYN+tXkhH31EfbpOPMFPLurQFG5heG7spf1LxNybHd3tYUPm+/3n1tAZpWAzcGjHm03Ubw0ByM0zNt+fDG3+VF80j/x9/v0SpXXpHxYVANHAm+w8It0EmWht2dYexQF8ixvmAqXKZu6b3vTqYSn3xSrEIucGaZ0F0kK/Khw4u+B/QLbkYvIPTAk0W/9vh+wTU+FTv fusionapp-entropy@drone"
            ]


standardContainer :: DebianSuite -> Architecture -> Property (HasInfo + Debian)
standardContainer suite arch =
  propertyList "standard container" $ props
  & osDebian suite arch
  & Systemd.running Systemd.networkd
  & "/etc/security/limits.d/10-local.conf" `File.hasContent`
  [ "* hard nofile 1000000"
  , "* soft nofile 1000000"
  ]
  & "/etc/default/locale"
  `File.hasContent`
  ["LANG=C.UTF-8"]
  & Apt.stdSourcesList `onChange` Apt.upgrade
  -- Need cron installed for unattended-upgrades to work
  & Apt.installed ["cron"]
  & Apt.removed ["exim4", "exim4-base", "exim4-config", "exim4-daemon-light"]
  `onChange` Apt.autoRemove
  & Apt.unattendedUpgrades
  & Apt.cacheCleaned


nginxPrimary :: Systemd.Container
nginxPrimary =
  Systemd.debContainer "nginx-primary" $ props
  & standardContainer (Stable "stretch") X86_64
  & File.dirExists "/etc/systemd/system/nginx.service.d"
  & "/etc/systemd/system/nginx.service.d/limits.conf" `File.hasContent`
  [ "[Service]"
  , "LimitNOFILE=100000"
  , "LimitCORE=500000000"
  ]
  & Apt.installed ["logrotate", "xz-utils"]
  & "/etc/logrotate.d/nginx"
  `File.hasContent`
  [ "/var/log/nginx/*.log {"
  , "    daily"
  , "    missingok"
  , "    rotate 30"
  , "    compress"
  , "    compresscmd /usr/bin/xz"
  , "    compressext .xz"
  , "    delaycompress"
  , "    notifempty"
  , "    create 0640 www-data adm"
  , "    sharedscripts"
  , "    prerotate"
  , "        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \\"
  , "            run-parts /etc/logrotate.d/httpd-prerotate; \\"
  , "        fi \\"
  , "    endscript"
  , "    postrotate"
  , "        invoke-rc.d nginx rotate >/dev/null 2>&1"
  , "    endscript"
  , "}"
  ]
  & Systemd.running "nginx" `requires` Nginx.installed
  & Systemd.bind ("/srv/certs" :: String)
  & Git.cloned (User "root") "https://github.com/fusionapp/fusion-error.git" "/srv/nginx/fusion-error" Nothing
  & File.dirExists "/srv/nginx/cache"
  & File.ownerGroup "/srv/nginx/cache" (User "www-data") (Group "www-data")
  & entropySite
  & File.dirExists "/srv/www/fusiontest.net"
  & File.dirExists "/srv/www/fusionapp.com"
  & fusionSites
  & Apt.installedBackport ["certbot"]
  & Systemd.disabled "certbot.timer"
  & Systemd.stopped "certbot.timer"
  & lets "fusiontest.net" [] "/srv/www/fusiontest.net"
  `onChange` Nginx.reloaded
  & lets "fusionapp.com"
  [ "entropy.fusionapp.com"
  , "bz-entropy.fusionapp.com"
  , "bz-ext.fusionapp.com"
  , "prod.fusionapp.com"
  , "bz.fusionapp.com"
  , "bn.fusionapp.com"
  ] "/srv/www/fusionapp.com"
  `onChange` Nginx.reloaded


lets :: Domain -> [Domain] -> LetsEncrypt.WebRoot -> Property DebianLike
lets = LetsEncrypt.letsEncrypt'
  (LetsEncrypt.AgreeTOS (Just "dev@fusionapp.com"))


entropySite :: RevertableProperty DebianLike DebianLike
entropySite =
  Nginx.siteEnabled "entropy.fusionapp.com"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    server_name         entropy.fusionapp.com entropy.fusiontest.net bz-entropy.fusionapp.com;"
  , "    access_log          /var/log/nginx/entropy.access.log;"
  , "    gzip                off;"
  , ""
  , "    location '/.well-known/acme-challenge' {"
  , "        default_type 'text/plain';"
  , "        root /srv/www/fusionapp.com;"
  , "    }"
  , ""
  , "    location / {"
  , "        client_max_body_size    512m;"
  , "        proxy_pass              http://41.72.130.253:8000;"
  , "        proxy_set_header        Host            $host;"
  , "        proxy_set_header        X-Real-IP       $remote_addr;"
  , "        proxy_read_timeout      60;"
  , "        proxy_buffering         off;"
  , "    }"
  , ""
  , "    location /new {"
  , "        client_max_body_size    512m;"
  , "        proxy_pass              http://41.72.130.253:8000;"
  , "        proxy_set_header        Host            $host;"
  , "        proxy_set_header        X-Real-IP       $remote_addr;"
  , "        proxy_read_timeout      60;"
  , "        proxy_buffering         off;"
  , "        allow 10.42.0.0/16;"
  , "        allow 172.17.0.0/16;"
  , "        allow 192.168.50.10;"
  , "        allow 197.189.229.122;"
  , "        allow 41.72.130.248/29;"
  , "        allow 41.72.135.84;"
  , "        deny all;"
  , "    }"
  , "}"
  ]


fusionSites :: Property DebianLike
fusionSites =
  propertyList "Fusion sites" $ props
  & Nginx.siteEnabled "fusion-prod-bz"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    listen              41.72.130.253:443 default ssl;"
  , "    server_name         fusionapp.com bz-ext.fusionapp.com bz.fusionapp.com prod.fusionapp.com bn.fusionapp.com;"
  , "    ssl_certificate     " <> LetsEncrypt.fullChainFile "fusionapp.com" <> ";"
  , "    ssl_certificate_key " <> LetsEncrypt.privKeyFile "fusionapp.com" <> ";"
  --, "    ssl_certificate     /srv/certs/private/star.fusionapp.com.pem;"
  --, "    ssl_certificate_key /srv/certs/private/star.fusionapp.com.pem;"
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_ciphers         EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;"
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
  , "    ssl_dhparam         /srv/certs/dhparam.pem;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}.access.log;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript application/javascript text/css text/csv text/tab-separated-values text/plain;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_set_header    X-Forwarded-Proto $scheme;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    add_header \"X-UA-Compatible\" \"IE=edge\";"
  , "    add_header Strict-Transport-Security \"max-age=31536000\";"
  , ""
  , "    location /fusion-error {"
  , "        root            /srv/nginx;"
  , "    }"
  , ""
  , "    error_page  502     /fusion-error/502.html;"
  , "    error_page  504     /fusion-error/504.html;"
  , ""
  , "    location '/.well-known/acme-challenge' {"
  , "        default_type 'text/plain';"
  , "        root /srv/www/fusionapp.com;"
  , "    }"
  , ""
  , "    location /__jsmodule__/ {"
  , "        root            /srv/nginx/cache;"
  , "        expires         max;"
  , "        add_header      \"Cache-Control\" \"public\";"
  , "        default_type    application/javascript;"
  , "        gzip_types      text/javascript application/javascript application/octet-stream text/plain;"
  , "        error_page      404 = @fetch;"
  , "        log_not_found   off;"
  , "    }"
  , ""
  , "    location @fetch {"
  , "        internal;"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "        proxy_store             on;"
  , "        proxy_store_access      user:rw  group:rw  all:r;"
  , "        proxy_temp_path         /srv/nginx/tmp;"
  , "        proxy_set_header        Accept-Encoding  \"\";"
  , "        root                    /srv/nginx/cache;"
  , "    }"
  , ""
  , "    location /static {"
  , "        expires                 30m;"
  , "        add_header              \"Cache-Control\" \"public\";"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location /Fusion/documents {"
  , "        expires                 max;"
  , "        add_header              \"Cache-Control\" \"public\";"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location /users {"
  , "        if ($scheme = http) {"
  , "            return 302 https://$host$request_uri;"
  , "        }"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location /private {"
  , "        if ($scheme = http) {"
  , "            return 302 https://$host$request_uri;"
  , "        }"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location = / {"
  , "        rewrite ^ https://$host/private/ redirect;"
  , "    }"
  , ""
  , "    location / {"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , "}"
  ]
  & Nginx.siteEnabled "fusion-uat"
  [ "server {"
  , "    listen              41.72.130.253:80;"
  , "    listen              41.72.130.253:443 ssl;"
  , "    server_name         fusiontest.net t0.fusiontest.net t1.fusiontest.net tc.fusiontest.net td.fusiontest.net te.fusiontest.net tf.fusiontest.net;"
  , "    ssl_dhparam         /srv/certs/dhparam.pem;"
  , "    ssl_certificate     " <> LetsEncrypt.fullChainFile "fusiontest.net" <> ";"
  , "    ssl_certificate_key " <> LetsEncrypt.privKeyFile "fusiontest.net" <> ";"
  , "    ssl_ciphers         EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;"
  , "    ssl_ecdh_curve      secp384r1;"
  , "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;"
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
  , "    root                /srv/nginx;"
  , "    access_log          /var/log/nginx/${host}.access.log;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          application/javascript text/javascript text/css text/csv text/tab-separated-values text/plain;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_set_header    X-Forwarded-Proto $scheme;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    add_header \"X-UA-Compatible\" \"IE=edge\";"
  , "    add_header Strict-Transport-Security \"max-age=31536000\";"
  , "    add_header X-Content-Type-Options nosniff;"
  , "    add_header x-frame-options SAMEORIGIN;"
  , "    add_header X-Xss-Protection \"1; mode=block; report=https://fusionapp.report-uri.com/r/d/xss/enforce\";"
  , "    add_header Referrer-Policy strict-origin-when-cross-origin;"
  , "    add_header Expect-CT \"max-age=0, report-uri=https://fusionapp.report-uri.com/r/d/ct/reportOnly\";"
  , "    add_header Content-Security-Policy-Report-Only \"img-src 'self' https://piwik.fusionapp.com; style-src blob: 'self' 'unsafe-inline'; connect-src https://sentry.fusionapp.com 'self'; script-src 'self' https://piwik.fusionapp.com 'unsafe-inline' 'unsafe-eval'; form-action 'self'; frame-ancestors 'none'; report-uri https://fusionapp.report-uri.com/r/d/csp/reportOnly\";"
  , ""
  , "    location /fusion-error {"
  , "        root            /srv/nginx;"
  , "    }"
  , ""
  , "    error_page  502     /fusion-error/502.html;"
  , "    error_page  504     /fusion-error/504.html;"
  , ""
  , "    location '/.well-known/acme-challenge' {"
  , "        default_type 'text/plain';"
  , "        root /srv/www/fusiontest.net;"
  , "    }"
  , ""
  , "    location /__jsmodule__/ {"
  , "        root            /srv/nginx/cache;"
  , "        expires         max;"
  , "        default_type    text/javascript;"
  , "        gzip_types      text/javascript application/javascript application/octet-stream text/plain;"
  , "        error_page      404 = @fetch;"
  , "        log_not_found   off;"
  , "    }"
  , ""
  , "    location /static {"
  , "        expires         30m;"
  , "        proxy_pass      http://41.72.135.84;"
  , "        proxy_redirect  http://fusiontest.net/ $scheme://fusiontest.net/;"
  , "    }"
  , ""
  , "    location @fetch {"
  , "        internal;"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          http://fusiontest.net/ $scheme://fusiontest.net/;"
  , "        proxy_redirect          https://fusiontest.net/ $scheme://fusiontest.net/;"
  , "        proxy_buffering         on;"
  , "        proxy_store             on;"
  , "        proxy_store_access      user:rw  group:rw  all:r;"
  , "        proxy_temp_path         /srv/nginx/tmp;"
  , "        root                    /srv/nginx/cache;"
  , "    }"
  , ""
  , "    location /Fusion/documents {"
  , "        expires                 max;"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          http://fusiontest.net/ $scheme://fusiontest.net/;"
  , "        proxy_redirect          https://fusiontest.net/ $scheme://fusiontest.net/;"
  , "    }"
  , ""
  , "    location /users {"
  , "        if ($scheme = http) {"
  , "            return 302 https://$host$request_uri;"
  , "        }"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location /private {"
  , "        if ($scheme = http) {"
  , "            return 302 https://$host$request_uri;"
  , "        }"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , ""
  , "    location = / {"
  , "        rewrite ^ https://$host/private/ redirect;"
  , "    }"
  , ""
  , "    location / {"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          https?://([^/]+)/ $scheme://$1/;"
  , "    }"
  , "}"
  ]


duplicityLocksCleaned :: RevertableProperty UnixLike UnixLike
duplicityLocksCleaned =
  confpath `File.hasContent` ["r! /srv/duplicity/cache/*/lockfile.lock"]
  <!> File.notPresent confpath
  where confpath = "/etc/tmpfiles.d/duplicity-lockfiles.conf"


fusionDumpsCleaned :: RevertableProperty UnixLike UnixLike
fusionDumpsCleaned =
  confpath `File.hasContent` ["d /srv/db/fusion/dumps 0755 root root 30d -"]
  <!> File.notPresent confpath
  where confpath = "/etc/tmpfiles.d/fusion-dumps.conf"


caddyfile :: Property UnixLike
caddyfile = propertyList "Configuration for Caddy" $ props
  & File.dirExists "/srv/caddy"
  & File.hasContent "/srv/caddy/Caddyfile"
  [ "https://rancher.fusionapp.com:443, https://rancher.fusionapp.com:4433"
  , "gzip"
  , "log stdout"
  , "proxy / rancher-server:8080 {"
  , " transparent"
  , " websocket"
  , "}"
  , "timeouts 5m"
  ]


prometheusConfig :: Property (HasInfo + UnixLike)
prometheusConfig =
  propertyList "Configuration for Prometheus" $ props
  & File.dirExists "/srv/prometheus"
  & File.dirExists "/srv/prometheus/storage"
  & File.ownerGroup "/srv/prometheus/storage" (User "nobody") (Group "nogroup")
  & prometheusRulesCfg
  & File.hasPrivContent "/srv/prometheus/drone-token" (Context "fusion production")
  & File.ownerGroup "/srv/prometheus/drone-token" (User "nobody") (Group "nogroup")
  & File.hasContent "/srv/prometheus/prometheus.yml" $(sourceFile "files/prometheus/prometheus-nonprod.yml")


prometheusProdConfig :: Property UnixLike
prometheusProdConfig =
  propertyList "Configuration for Prometheus (production)" $ props
  & File.dirExists "/srv/prometheus"
  & File.dirExists "/srv/prometheus/storage"
  & File.ownerGroup "/srv/prometheus/storage" (User "nobody") (Group "nogroup")
  & prometheusRulesCfg
  & File.hasContent "/srv/prometheus/prometheus.yml" $(sourceFile "files/prometheus/prometheus-prod.yml")


prometheusRulesCfg :: Property UnixLike
prometheusRulesCfg =
  "/srv/prometheus/recording.rules.yml" `File.hasContent` $(sourceFile "files/prometheus/recording.rules.yml")
