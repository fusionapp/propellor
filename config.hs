-- This is the main configuration file for Propellor, and is used to build
-- the propellor program.

import           Propellor
import           Propellor.CmdLine
--import Propellor.Property.Scheduled
import qualified Propellor.Property.File as File
import qualified Propellor.Property.Apt as Apt
--import qualified Propellor.Property.Network as Network
import qualified Propellor.Property.Ssh as Ssh
import qualified Propellor.Property.Cron as Cron
import qualified Propellor.Property.Systemd as Systemd
import qualified Propellor.Property.Sudo as Sudo
import qualified Propellor.Property.User as User
import qualified Propellor.Property.Hostname as Hostname
--import qualified Propellor.Property.Tor as Tor
--import qualified Propellor.Property.Docker as Docker

main :: IO ()
main = defaultMain hosts

-- The hosts propellor knows about.
-- Edit this to configure propellor!
hosts :: [Host]
hosts = [ scarlet
        ]

scarlet :: Host
scarlet = standardSystem "scarlet.fusionapp.com" (Stable "jessie") "amd64"
          & ipv4 "197.189.229.122"
          & "/etc/timezone" `File.hasContent` ["Africa/Johannesburg"]

standardSystem :: HostName -> DebianSuite -> Architecture -> Host
standardSystem hn suite arch =
  host hn
  & os (System (Debian suite) arch)
  & Hostname.sane
  & Hostname.searchDomain
  & Apt.stdSourcesList
  & Apt.unattendedUpgrades
  & Apt.installed ["openssh-server", "openssh-client", "git"]
  & Apt.serviceInstalledRunning "ntp"
  & Systemd.installed
  & Systemd.persistentJournal
  & Cron.runPropellor (Cron.Times "30 * * * *")
  -- & Ssh.passwordAuthentication False
  & Ssh.randomHostKeys
  & Ssh.permitRootLogin True
  & Apt.installed ["sudo"]
  & propertyList "admin accounts" (map User.accountFor admins
                                   ++ map User.lockedPassword admins
                                   ++ map Sudo.enabledFor admins)
  & adminKeys (User "root")
  & tristanKeys (User "tristan")
  where admins = map User ["tristan", "jj", "darren"]

tristanKeys :: User -> Property NoInfo
tristanKeys user = propertyList "keys for tristan" (map (Ssh.authorizedKey user)
                 [ "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTItuXoGILFK8Y7+y07e5pomUwNfsvptD/jiep8MA8ChcVYZMe/Pl++eBXPz71fjGUWR8H86chPYa5omMLaaJQ0KNjmqzyp27GKVxrSYxt3pkv34xkxkN0HYoGRR6a7JiV2vjOI7Av71lh6WOMA315I+y7vpIenLU/kWiy/YkRO6fe7Bh9ZbMCspmREupsnHH8Zxu13xakQFZ2OzxhbDjWDHG42zZnbR3KCEVAE5/IM+RREZfFGiqTlbCEe2pCRKAntk2CS9E9f360KxMerRJAoQtHzuF1EZ+A1rn2lNLm9KW7n99EyuUt5W1E0dnB0Au7uYs7tUyAKjIZIg9OrHjR cardno:000603011845"
                 , "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOg4PwvtqWHhan0rGxKAQn+n1IIKJJ0JsTMFdZiTFeOj mithrandi@lorien"
                 ])

adminKeys :: User -> Property NoInfo
adminKeys user = propertyList "admin keys" . map ($ user) $
                 [ tristanKeys
                 ]
