import           Control.Applicative ((<$>), (<*>))
import           Propellor
import           Propellor.Base
import qualified Propellor.Property.Apache as Apache
import qualified Propellor.Property.Apt as Apt
import qualified Propellor.Property.Cron as Cron
import qualified Propellor.Property.File as File
import qualified Propellor.Property.Git as Git
import qualified Propellor.Property.Hostname as Hostname
import qualified Propellor.Property.LetsEncrypt as LetsEncrypt
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
scarlet = host "scarlet.fusionapp.com" $ props
          & standardSystem (Stable "jessie") X86_64
          & ipv4 "197.189.229.122"
          & hetznerResolv
          & fusionHost
          -- Local private certificates
          & File.dirExists "/srv/certs/private"
          & File.hasPrivContent "/srv/certs/private/fusiontest.net-fusionca.crt.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/scarlet.fusionapp.com.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/mfc-fusion-uat.pem" hostContext
          & File.hasPrivContent "/srv/certs/private/mfc-fusion-jwt-uat.pem" hostContext
          & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/scarlet.fusionapp.com.pem"
          & Cron.niceJob "fusion-backup" (Cron.Times "23 3 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-eu-uat.fusionapp.com"
          & caddyfile
          & File.dirExists "/srv/catcher-in-the-rye"
          & File.hasPrivContent "/srv/catcher-in-the-rye/config.yaml" (Context "fusion aux")
          & File.dirExists "/srv/prometheus"
          & prometheusConfig


onyx :: Host
onyx = host "onyx.fusionapp.com" $ props
       & standardSystem (Stable "jessie") X86_64
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
       & File.hasPrivContent "/srv/certs/private/fusiontest.net.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/quotemaster.co.za.pem" (Context "fusion production")
       & File.dirExists "/etc/docker/certs.d/scarlet.fusionapp.com:5000"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.cert" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       & "/etc/docker/certs.d/scarlet.fusionapp.com:5000/client.key" `File.isSymlinkedTo` File.LinkTarget "/srv/certs/private/onyx.fusionapp.com.pem"
       -- Work around Propellor issue, not sure exactly what is wrong here.
       & Apt.installed ["debootstrap"]
       & Systemd.running Systemd.networkd
       & Systemd.nspawned nginxPrimary
       & Systemd.nspawned apacheSvn
       & Systemd.nspawned mailRelayContainer
       & Cron.job "fusion-index-backup" (Cron.Times "41 1 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-index /srv/db/fusion-index s3://s3-eu-west-1.amazonaws.com/backups-fusion-index.fusionapp.com"
       & Cron.job "fusion-prod backup" (Cron.Times "17 0-23/4 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion-prod /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-fusion-prod.fusionapp.com"
       & Cron.job "fusion-prod nightly deploy" (Cron.Times "7 1 * * *") (User "root") "/srv/fab" "git fetch && git reset --hard origin/master && git clean -dfx && fab fusion.deploy"
       & Cron.job "weekly btrfs balance" (Cron.Times "18 3 * * Sun") (User "root") "/tmp" "/bin/btrfs balance start -v -dusage=50 -musage=50 /"
       & fusionDumpsCleaned
       where pubKeyEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdsS9oJKqICEvhJFHP4LQTjwso9QHSLTtjcBZR2r6kL root@onyx.fusionapp.com"
             pubKeyEcdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN3UsIwUsSCgItsJv6gdisBYfuxIwP5/jhfe+g1JD6NXqzgj7mUGjMO+tiatgNYauqaFB3JPoS2NsPo6t0jKbzs= root@onyx.fusionapp.com"


fusionHost :: Property (HasInfo + DebianLike)
fusionHost = propertyList "Platform dependencies for Fusion services" $ props
             & "/etc/timezone" `File.hasContent` ["Africa/Johannesburg"]
             & Apt.installed ["mercurial", "git"]
             -- Upgraded Docker
             & Apt.installed ["docker-engine"]
             `requires` Apt.setSourcesListD ["deb https://apt.dockerproject.org/repo debian-jessie main"] "docker"
             `requires` Apt.installed ["apt-transport-https"]
             `requires` Apt.trustsKey dockerKey
             `requires` dockerOptions
             & propertyList "admin docker access"
             (toProps (flip User.hasGroup (Group "docker") <$> admins))
             & File.dirExists "/srv/duplicity"
             & File.hasPrivContent "/srv/duplicity/credentials.sh" hostContext
             & File.dirExists "/srv/locks"
             & Cron.niceJob "update fusion-fab" Cron.Daily (User "root") "/srv/fab" "/usr/bin/git fetch && /usr/bin/git reset --hard && /usr/bin/git clean -dfx"
             `requires` Git.cloned (User "root") "https://github.com/fusionapp/fusion-fab.git" "/srv/fab" Nothing
             & Apt.installed ["fabric"]
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
  , "mQINBFWln24BEADrBl5p99uKh8+rpvqJ48u4eTtjeXAWbslJotmC/CakbNSqOb9o"
  , "ddfzRvGVeJVERt/Q/mlvEqgnyTQy+e6oEYN2Y2kqXceUhXagThnqCoxcEJ3+KM4R"
  , "mYdoe/BJ/J/6rHOjq7Omk24z2qB3RU1uAv57iY5VGw5p45uZB4C4pNNsBJXoCvPn"
  , "TGAs/7IrekFZDDgVraPx/hdiwopQ8NltSfZCyu/jPpWFK28TR8yfVlzYFwibj5WK"
  , "dHM7ZTqlA1tHIG+agyPf3Rae0jPMsHR6q+arXVwMccyOi+ULU0z8mHUJ3iEMIrpT"
  , "X+80KaN/ZjibfsBOCjcfiJSB/acn4nxQQgNZigna32velafhQivsNREFeJpzENiG"
  , "HOoyC6qVeOgKrRiKxzymj0FIMLru/iFF5pSWcBQB7PYlt8J0G80lAcPr6VCiN+4c"
  , "NKv03SdvA69dCOj79PuO9IIvQsJXsSq96HB+TeEmmL+xSdpGtGdCJHHM1fDeCqkZ"
  , "hT+RtBGQL2SEdWjxbF43oQopocT8cHvyX6Zaltn0svoGs+wX3Z/H6/8P5anog43U"
  , "65c0A+64Jj00rNDr8j31izhtQMRo892kGeQAaaxg4Pz6HnS7hRC+cOMHUU4HA7iM"
  , "zHrouAdYeTZeZEQOA7SxtCME9ZnGwe2grxPXh/U/80WJGkzLFNcTKdv+rwARAQAB"
  , "tDdEb2NrZXIgUmVsZWFzZSBUb29sIChyZWxlYXNlZG9ja2VyKSA8ZG9ja2VyQGRv"
  , "Y2tlci5jb20+iQI4BBMBAgAiBQJVpZ9uAhsvBgsJCAcDAgYVCAIJCgsEFgIDAQIe"
  , "AQIXgAAKCRD3YiFXLFJgnbRfEAC9Uai7Rv20QIDlDogRzd+Vebg4ahyoUdj0CH+n"
  , "Ak40RIoq6G26u1e+sdgjpCa8jF6vrx+smpgd1HeJdmpahUX0XN3X9f9qU9oj9A4I"
  , "1WDalRWJh+tP5WNv2ySy6AwcP9QnjuBMRTnTK27pk1sEMg9oJHK5p+ts8hlSC4Sl"
  , "uyMKH5NMVy9c+A9yqq9NF6M6d6/ehKfBFFLG9BX+XLBATvf1ZemGVHQusCQebTGv"
  , "0C0V9yqtdPdRWVIEhHxyNHATaVYOafTj/EF0lDxLl6zDT6trRV5n9F1VCEh4Aal8"
  , "L5MxVPcIZVO7NHT2EkQgn8CvWjV3oKl2GopZF8V4XdJRl90U/WDv/6cmfI08GkzD"
  , "YBHhS8ULWRFwGKobsSTyIvnbk4NtKdnTGyTJCQ8+6i52s+C54PiNgfj2ieNn6oOR"
  , "7d+bNCcG1CdOYY+ZXVOcsjl73UYvtJrO0Rl/NpYERkZ5d/tzw4jZ6FCXgggA/Zxc"
  , "jk6Y1ZvIm8Mt8wLRFH9Nww+FVsCtaCXJLP8DlJLASMD9rl5QS9Ku3u7ZNrr5HWXP"
  , "HXITX660jglyshch6CWeiUATqjIAzkEQom/kEnOrvJAtkypRJ59vYQOedZ1sFVEL"
  , "MXg2UCkD/FwojfnVtjzYaTCeGwFQeqzHmM241iuOmBYPeyTY5veF49aBJA1gEJOQ"
  , "TvBR8Q=="
  , "=Fm3p"
  , "-----END PGP PUBLIC KEY BLOCK-----"
  ]


dockerOptions :: Property UnixLike
dockerOptions = propertyList "Docker options" $ props
  & File.dirExists "/etc/systemd/system/docker.service.d"
  & File.hasContent "/etc/systemd/system/docker.service.d/options.conf"
  [ "[Service]"
  , "ExecStart="
  , unwords
    [ "ExecStart=/usr/bin/docker daemon -H fd://"
    , "--registry-mirror https://scarlet.fusionapp.com:5002"
    , "--userland-proxy=false"
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
              & File.hasContent "/srv/certs/dhparam.pem" dhparam2048
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
   , Sudo.enabledFor
   , flip User.hasGroup (Group "systemd-journal")
   , flip User.hasGroup (Group "adm")
   ] <*> admins)
  & adminKeys (User "root")
  & tristanKeys (User "tristan")
  & jjKeys (User "jj")
  & darrenKeys (User "darren")
  ! williamKeys (User "root")
  ! williamKeys (User "william")
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
          "/etc/ssmtp/ssmtp.conf" `File.hasContent`
          [ "Root=dev@fusionapp.com"
          , "Mailhub=smtp.fusionapp.com:587"
          , "RewriteDomain=fusionapp.com"
          , "FromLineOverride=yes"
          ] `requires` Apt.installed ["ssmtp"]


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


williamKeys :: User -> Property UnixLike
williamKeys user = propertyList "keys for william"
                   . toProps
                   . map (setupRevertableProperty . Ssh.authorizedKey user) $
                   [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiy5Sx5pADzWP9Aq+ecagisuc2jZJaR/DV4PoVWxNAH4HngybzBBUtTL/9BsLcTn5OKNGqc1Kk916PENBPN3sqNQJj1u+OUyibAT8Em/sEfaDZ5ykh++E0/ycKYFs2chXR7fPhe+68hLAMNS3GlKvf5ErmScz3oyDEwR73b00LfABz3rpy7YuxoNiA/PgPv4+5oaULUxo0ysGx+mcoAvrXwQ5u3KHPOKNNzN9E3gF5AhML+qGF5i7T3dYcZ0OsqkEJ4gSRG8PPVmX2rKMI+Ldvh0LI0Xa9fgaEgtC5X38u+0WalEE5EhBv5LUZKRu+9bzkR71jl9kbI86ld/QLYf9Z js@mvp.gg"
                   ]


adminKeys :: User -> Property UnixLike
adminKeys user = propertyList "admin keys" . toProps . map ($ user) $
                 [ tristanKeys
                 , jjKeys
                 , darrenKeys
                 , williamKeys
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


apacheSvn :: Systemd.Container
apacheSvn = Systemd.debContainer "apache-svn" $ props
  & standardContainer (Stable "jessie") X86_64
  & Systemd.bind ("/srv/svn" :: String)
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


nginxPrimary :: Systemd.Container
nginxPrimary =
  Systemd.debContainer "nginx-primary" $ props
  & standardContainer (Stable "jessie") X86_64
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
  & svnSite
  & andersonSite
  & entropySite
  & File.dirExists "/srv/www/fusiontest.net"
  & fusionSites
  & lets "fusiontest.net" "/srv/www/fusiontest.net"
  `onChange` Nginx.reloaded
  & Apt.installedBackport ["certbot"]
  & File.dirExists "/srv/www/quotemaster.co.za"
  & quotemasterSite
  & lets "quotemaster.co.za" "/srv/www/quotemaster.co.za"
  `onChange` Nginx.reloaded
  & File.dirExists "/srv/www/mcibrokerquotes.co.za"
  & mcibrokerSite
  & lets "mcibrokerquotes.co.za" "/srv/www/mcibrokerquotes.co.za"
  `onChange` Nginx.reloaded
  & saxumSite
  & saxumBrokersSite


lets :: Domain -> LetsEncrypt.WebRoot -> Property DebianLike
lets = LetsEncrypt.letsEncrypt
  (LetsEncrypt.AgreeTOS (Just "dev@fusionapp.com"))


svnSite :: RevertableProperty DebianLike DebianLike
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
  , "        proxy_pass       http://127.0.0.1:8100;"
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
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
  , "    access_log          /var/log/nginx/svn.fusionapp.com_tls_access.log;"
  , "    client_max_body_size 200m;"
  , ""
  , "    location / {"
  , "        proxy_set_header Host $host;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto http;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://127.0.0.1:8100;"
  , "    }"
  , "}"
  ]


andersonSite :: RevertableProperty DebianLike DebianLike
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


mcibrokerSite :: RevertableProperty DebianLike DebianLike
mcibrokerSite =
  Nginx.siteEnabled "mcibroker"
  [ "server {"
  , "    listen              41.72.131.181:80;"
  , "    server_name         mcibrokerquotes.co.za www.mcibrokerquotes.co.za;"
  , "    access_log          /var/log/nginx/mcibrokerquotes.co.za.access.log;"
  , "    location / {"
  , "        rewrite ^(.*)$ https://mcibrokerquotes.co.za$1 permanent;"
  , "    }"
  , "    location '/.well-known/acme-challenge' {"
  , "        default_type 'text/plain';"
  , "        root /srv/www/mcibrokerquotes.co.za;"
  , "    }"
  , "}"
  , ""
  , "server {"
  , "    listen              41.72.131.181:443 ssl;"
  , "    server_name         mcibrokerquotes.co.za;"
  , "    ssl_certificate     " <> LetsEncrypt.fullChainFile "mcibrokerquotes.co.za" <> ";"
  , "    ssl_certificate_key " <> LetsEncrypt.privKeyFile "mcibrokerquotes.co.za" <> ";"
  , "    ssl_ciphers         ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AES:RSA+3DES:!ADH:!AECDH:!MD5;"
  , "    ssl_dhparam         /srv/certs/dhparam.pem;"
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;"
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
  , "    access_log          /var/log/nginx/mcibrokerquotes.co.za_tls.access.log;"
  , "    location / {"
  , "        add_header X-Frame-Options SAMEORIGIN;"
  , "        proxy_read_timeout 10m;"
  , "        proxy_set_header Host quotemaster.co.za;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto https;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://41.72.129.157/mci/;"
  , "    }"
  , "}"
  ]


entropySite :: RevertableProperty DebianLike DebianLike
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


fusionSites :: Property DebianLike
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
  , "    gzip_types          text/javascript application/javascript text/css text/csv text/tab-separated-values text/plain;"
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
  , "        proxy_pass              http://41.72.130.249:8001;"
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
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "    }"
  , ""
  , "    location /Fusion/documents {"
  , "        expires                 max;"
  , "        proxy_pass              http://41.72.130.249:8001;"
  , "    }"
  , ""
  , "    location / {"
  , "        if ($proxy_encoding != identity) {"
  , "            proxy_pass http://127.0.0.1;"
  , "            break;"
  , "        }"
  , "        proxy_pass              http://41.72.130.249:8001;"
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
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_ciphers         EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:ECDHE-RSA-AES128-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA128:DHE-RSA-AES128-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA128:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA128:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA128:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA384:AES128-GCM-SHA128:AES128-SHA128:AES128-SHA128:AES128-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;"
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
  , "    ssl_dhparam         /srv/certs/dhparam.pem;"
  , "    gzip                on;"
  , "    gzip_proxied        any;"
  , "    gzip_disable        msie6;"
  , "    gzip_comp_level     9;"
  , "    gzip_types          text/javascript application/javascript text/css text/csv text/tab-separated-values text/plain;"
  , "    proxy_buffering     on;"
  , "    proxy_set_header    Host            $host;"
  , "    proxy_set_header    X-Real-IP       $remote_addr;"
  , "    proxy_read_timeout  600;"
  , "    proxy_http_version  1.1;"
  , "    client_max_body_size 512m;"
  , ""
  , "    location /fusion-endpoints {"
  , "        proxy_pass          http://41.72.130.249:8001/fusion-endpoints;"
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
  , "    location = / {"
  , "        rewrite ^ $scheme://$host/private/ redirect;"
  , "    }"
  , ""
  , "    location / {"
  , "        proxy_pass              http://41.72.135.84;"
  , "        proxy_redirect          http://fusiontest.net/ $scheme://fusiontest.net/;"
  , "        proxy_redirect          https://fusiontest.net/ $scheme://fusiontest.net/;"
  , "    }"
  , "}"
  ]
  ! Nginx.siteEnabled "fusion-uat-tls" []


quotemasterSite :: RevertableProperty DebianLike DebianLike
quotemasterSite =
  Nginx.siteEnabled "quotemaster"
  [ "server {"
  , "    listen              41.72.131.181:80;"
  , "    server_name         quotemaster.co.za www.quotemaster.co.za;"
  , "    access_log          /var/log/nginx/quotemaster.co.za.access.log;"
  , "    location / {"
  , "        rewrite ^(.*)$ https://quotemaster.co.za$1 permanent;"
  , "    }"
  , "    location '/.well-known/acme-challenge' {"
  , "        default_type 'text/plain';"
  , "        root /srv/www/quotemaster.co.za;"
  , "    }"
  , "}"
  , ""
  , "server {"
  , "    listen              41.72.131.181:443 default ssl;"
  , "    server_name         quotemaster.co.za;"
  , "    ssl_certificate     " <> LetsEncrypt.fullChainFile "quotemaster.co.za" <> ";"
  , "    ssl_certificate_key " <> LetsEncrypt.privKeyFile "quotemaster.co.za" <> ";"
  , "    ssl_ciphers         ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AES:RSA+3DES:!ADH:!AECDH:!MD5;"
  , "    ssl_dhparam         /srv/certs/dhparam.pem;"
  , "    ssl_prefer_server_ciphers on;"
  , "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;"
  , "    ssl_session_cache   none;"
  , "    ssl_session_tickets off;"
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


saxumSite :: RevertableProperty DebianLike DebianLike
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


saxumBrokersSite :: RevertableProperty DebianLike DebianLike
saxumBrokersSite =
  Nginx.siteEnabled "saxumbrokers.co.za"
  [ "server {"
  , "    listen              41.72.131.181:80;"
  , "    server_name         www.saxumbrokers.co.za saxumbrokers.co.za;"
  , "    access_log          /var/log/nginx/saxumbrokers.access.log;"
  , "    location / {"
  , "        proxy_read_timeout 5m;"
  , "        proxy_set_header Host quotemaster.co.za;"
  , "        proxy_set_header X-Real-IP $remote_addr;"
  , "        proxy_set_header X-Forwarded-Proto http;"
  , "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
  , "        proxy_pass       http://41.72.129.157/saxumbroker/;"
  , "    }"
  , "}"
  ]


mailRelayContainer :: Systemd.Container
mailRelayContainer =
  Systemd.debContainer "mail-relay" $ props
  & standardContainer (Stable "jessie") X86_64
  & mailRelay


mailRelay :: Property DebianLike
mailRelay =
  propertyList "fusionapp.com mail relay" $ props
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
  , "timeouts 0"
  ]


prometheusConfig :: Property (HasInfo + DebianLike)
prometheusConfig = withPrivData src ctx $
  \gettoken -> property' "Prometheus configuration" $
              \p -> gettoken $ \token -> ensureProperty p $
                                       "/srv/prometheus/prometheus.yml"
                                       `File.hasContent`
                                       cfg (privDataVal token)
  where src = Password "weave cloud token"
        ctx = Context "Fusion production"
        cfg token =
          [ "global:"
          , "  external_labels:"
          , "    deployment: 'testing'"
          , "scrape_configs:"
          , "  - job_name: 'prometheus'"
          , "    static_configs:"
          , "      - targets: ['localhost:9090']"
          , "  - job_name: 'HostsMetrics'"
          , "    dns_sd_configs:"
          , "      - names:"
          , "        - node-exporter"
          , "        refresh_interval: 15s"
          , "        type: A"
          , "        port: 9100"
          , "remote_write:"
          , "  - url: https://cloud.weave.works/api/prom/push"
          , "    basic_auth:"
          , "      password: " <> token
          ]
