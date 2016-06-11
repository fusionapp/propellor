-- | Maintainer: Sean Whitton <spwhitton@spwhitton.name>

module Propellor.Property.HostingProvider.Exoscale (
	distroKernel,
) where

import Propellor.Base
import qualified Propellor.Property.Grub as Grub
import qualified Propellor.Property.Apt as Apt
import qualified Propellor.Property.Reboot as Reboot

-- | Current Exoshare Debian image doesn't install GRUB, so this property makes
-- sure GRUB is installed and we're running the distro's kernel
--
-- We reboot after doing this because 'Sbuild.built' will fail to set up an
-- overlay-type chroot on an old kernel
distroKernel :: Architecture -> Property DebianLike
distroKernel arch = combineProperties "boots distro kernel" $ props
	& Grub.installed' Grub.PC
	& Apt.installed ["linux-image-" ++ arch]
	& Grub.boots "/dev/vda"
	& flagFile
		(Grub.mkConfig `before` Reboot.now)
		"/etc/propellor-distro-kernel"
