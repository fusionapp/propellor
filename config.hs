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
        , onyxDr
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
          & Cron.niceJob "fusion-backup" (Cron.Times "23 3 * * *") (User "root") "/srv/duplicity" "/usr/local/bin/fusion-backup fusion /srv/db/fusion s3://s3-eu-west-1.amazonaws.com/backups-eu-uat.fusionapp.com"
          & caddyfile
          & File.dirExists "/srv/catcher-in-the-rye"
          & File.hasPrivContent "/srv/catcher-in-the-rye/config.yaml" (Context "fusion aux")
          & prometheusConfig
          & File.dirExists "/srv/drone-scheduler"
          & File.hasContent "/srv/drone-scheduler/schedules.yaml" $(sourceFile "files/drone-schedules.yaml")
          & File.dirExists "/srv/sentry"
          & File.hasPrivContent "/srv/sentry/config.yml" (Context "fusion aux")
          & File.ownerGroup "/srv/sentry/config.yml" (User "999") (Group "999")


onyx :: Host
onyx = host "onyx.fusionapp.com" $ props
       & standardSystem (Stable "stretch") X86_64
       & ipv4 "41.72.130.253"
       & hetznerResolv
       & fusionHost
       -- Local private certificates
       & File.dirExists "/srv/certs/private"
       & File.hasPrivContent "/srv/certs/private/onyx.fusionapp.com.pem" hostContext
       & File.hasPrivContent "/srv/certs/private/prod.fusionapp.com.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-jwt-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/fusiontest.net.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/ariva.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/absa-datapower-prod.pem" (Context "fusion production")
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


onyxDr :: Host
onyxDr = host "onyx-dr.fusionapp.com" $ props
       & standardSystem (Stable "stretch") X86_64
       & ipv4 undefined
       & fusionHost
       -- Local private certificates
       & File.dirExists "/srv/certs/private"
       & File.hasPrivContent "/srv/certs/private/onyx.fusionapp.com.pem" (Context "onyx.fusionapp.com")
       & File.hasPrivContent "/srv/certs/private/prod.fusionapp.com.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/sbvaf-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/mfc-fusion-jwt-prod.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/fusiontest.net.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/ariva.pem" (Context "fusion production")
       & File.hasPrivContent "/srv/certs/private/absa-datapower-prod.pem" (Context "fusion production")
       -- Work around Propellor issue, not sure exactly what is wrong here.
       & Apt.installed ["debootstrap"]
       & Apt.installed ["systemd-container"]
       & Systemd.running Systemd.networkd
       & Systemd.nspawned nginxDr
       & fusionDumpsCleaned
       & prometheusProdConfig


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
             & duplicityLocksCleaned


fusionCa :: [String]
fusionCa = $(sourceFile "files/fusion-ca.crt.pem")

dockerKey :: Apt.AptKey
dockerKey =
  Apt.AptKey "docker" $ unlines $(sourceFile "files/docker.asc")

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
admins = map User ["tristan", "jj"]


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


adminKeys :: User -> Property UnixLike
adminKeys user = propertyList "admin keys" . toProps . map ($ user) $
                 [ tristanKeys
                 , jjKeys
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
  & Nginx.installed
  & Systemd.bind ("/srv/certs" :: String)
  & Git.cloned (User "root") "https://github.com/fusionapp/fusion-error.git" "/srv/nginx/fusion-error" Nothing
  & File.dirExists "/srv/nginx/cache"
  & File.ownerGroup "/srv/nginx/cache" (User "www-data") (Group "www-data")
  & Nginx.siteEnabled "entropy.fusionapp.com" $(sourceFile "files/nginx/entropy.conf")
  & File.dirExists "/srv/www/fusiontest.net"
  & File.dirExists "/srv/www/fusionapp.com"
  & Nginx.siteEnabled "fusion-prod-bz" $(sourceFile "files/nginx/fusion-prod-bz.conf")
  & Nginx.siteEnabled "fusion-uat" $(sourceFile "files/nginx/fusion-uat.conf")
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


nginxDr :: Systemd.Container
nginxDr =
  Systemd.debContainer "nginx-dr" $ props
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
  & Nginx.installed
  & Systemd.bind ("/srv/certs" :: String)
  & Git.cloned (User "root") "https://github.com/fusionapp/fusion-error.git" "/srv/nginx/fusion-error" Nothing
  & File.dirExists "/srv/nginx/cache"
  & File.ownerGroup "/srv/nginx/cache" (User "www-data") (Group "www-data")
  & Nginx.siteEnabled "entropy.fusionapp.com" $(sourceFile "files/nginx/entropy.conf")
  & File.dirExists "/srv/www/fusionapp.com"
  & Nginx.siteEnabled "fusion-prod-dr" $(sourceFile "files/nginx/fusion-prod-dr.conf")
  & Apt.installedBackport ["certbot"]
  & Systemd.disabled "certbot.timer"
  & Systemd.stopped "certbot.timer"
  `onChange` Nginx.reloaded
  -- & lets "fusionapp.com"
  -- [ "entropy.fusionapp.com"
  -- , "bz-entropy.fusionapp.com"
  -- , "bz-ext.fusionapp.com"
  -- , "prod.fusionapp.com"
  -- , "bz.fusionapp.com"
  -- , "bn.fusionapp.com"
  -- ] "/srv/www/fusionapp.com"
  & lets "onyx-dr.fusionapp.com" [] "/srv/www/fusionapp.com"
  `onChange` Nginx.reloaded


lets :: Domain -> [Domain] -> LetsEncrypt.WebRoot -> Property DebianLike
lets = LetsEncrypt.letsEncrypt'
  (LetsEncrypt.AgreeTOS (Just "dev@fusionapp.com"))


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
