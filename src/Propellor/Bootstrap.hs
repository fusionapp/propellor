{-# LANGUAGE DeriveDataTypeable #-}

module Propellor.Bootstrap (
	Bootstrapper(..),
	Builder(..),
	defaultBootstrapper,
	getBootstrapper,
	bootstrapPropellorCommand,
	checkBinaryCommand,
	installGitCommand,
	buildPropellor,
	checkDepsCommand,
	buildCommand,
) where

import Propellor.Base
import Propellor.Types.Info
import Propellor.Git.Config

import System.Posix.Files
import Data.List

type ShellCommand = String

-- | Different ways that Propellor's dependencies can be installed,
-- and propellor can be built. The default is `Robustly Cabal`
--
-- `Robustly Cabal` and `Robustly Stack` use the OS's native packages
-- as much as possible to install Cabal, Stack, and propellor's build
-- dependencies. When necessary, dependencies are built from source
-- using Cabal or Stack rather than using the OS's native packages.
--
-- `OSOnly` uses the OS's native packages of Cabal and all of propellor's
-- build dependencies. It may not work on all systems.
data Bootstrapper = Robustly Builder | OSOnly
	deriving (Show, Typeable)

data Builder = Cabal | Stack
	deriving (Show, Typeable)

defaultBootstrapper :: Bootstrapper
defaultBootstrapper = Robustly Cabal

-- | Gets the Bootstrapper for the Host propellor is running on.
getBootstrapper :: Propellor Bootstrapper
getBootstrapper = go <$> askInfo
  where
	go NoInfoVal = defaultBootstrapper
	go (InfoVal bs) = bs

getBuilder :: Bootstrapper -> Builder
getBuilder (Robustly b) = b
getBuilder OSOnly = Cabal

-- Shell command line to ensure propellor is bootstrapped and ready to run.
-- Should be run inside the propellor config dir, and will install
-- all necessary build dependencies and build propellor.
bootstrapPropellorCommand :: Bootstrapper -> Maybe System -> ShellCommand
bootstrapPropellorCommand bs msys = checkDepsCommand bs msys ++
	"&& if ! test -x ./propellor; then "
		++ buildCommand bs ++
	"; fi;" ++ checkBinaryCommand bs

-- Use propellor --check to detect if the local propellor binary has
-- stopped working (eg due to library changes), and must be rebuilt.
checkBinaryCommand :: Bootstrapper -> ShellCommand
checkBinaryCommand bs = "if test -x ./propellor && ! ./propellor --check; then " ++ go (getBuilder bs) ++ "; fi"
  where
	go Cabal = intercalate " && "
		[ "cabal clean"
		, buildCommand bs
		]
	go Stack = intercalate " && "
		[ "stack clean"
		, buildCommand bs
		]

buildCommand :: Bootstrapper -> ShellCommand
buildCommand bs = intercalate " && " (go (getBuilder bs))
  where
	go Cabal =
		[ "cabal configure"
		, "cabal build -j1 propellor-config"
		, "ln -sf dist/build/propellor-config/propellor-config propellor"
		]
	go Stack =
		[ "stack build :propellor-config"
		, "ln -sf $(stack path --dist-dir)/build/propellor-config/propellor-config propellor"
		]

-- Check if all dependencies are installed; if not, run the depsCommand.
checkDepsCommand :: Bootstrapper -> Maybe System -> ShellCommand
checkDepsCommand bs sys = go (getBuilder bs)
  where
	go Cabal = "if ! cabal configure >/dev/null 2>&1; then " ++ depsCommand bs sys ++ "; fi"
	go Stack = "if ! stack build --dry-run >/dev/null 2>&1; then " ++ depsCommand bs sys ++ "; fi"

-- Install build dependencies of propellor, using the specified
-- Bootstrapper.
--
-- When bootstrapping Robustly, first try to install the builder, 
-- and all haskell libraries that propellor uses from OS packages.
-- Some packages may not be available in some versions of the OS,
-- or propellor may need a newer version. So, as a second step, 
-- ny other dependencies are installed from source using the builder.
--
-- Note: May succeed and leave some deps not installed.
depsCommand :: Bootstrapper -> Maybe System -> ShellCommand
depsCommand bs msys = "( " ++ intercalate " ; " (go bs) ++ ") || true"
  where
	go (Robustly Cabal) = osinstall Cabal ++
		[ "cabal update"
		, "cabal install --only-dependencies"
		]	
	go (Robustly Stack) = osinstall Stack ++ 
		[ "stack setup"
		, "stack build --only-dependencies :propellor-config"
		]
	go OSOnly = osinstall Cabal

	osinstall builder = case msys of
		Just (System (FreeBSD _) _) -> map pkginstall (fbsddeps builder)
		Just (System (ArchLinux) _) -> map pacmaninstall (archlinuxdeps builder)
		Just (System (Debian _ _) _) -> useapt builder
		Just (System (Buntish _) _) -> useapt builder
		-- assume a Debian derived system when not specified
		Nothing -> useapt builder

	useapt builder = "apt-get update" : map aptinstall (debdeps builder)

	aptinstall p = "DEBIAN_FRONTEND=noninteractive apt-get -qq --no-upgrade --no-install-recommends -y install " ++ p
	pkginstall p = "ASSUME_ALWAYS_YES=yes pkg install " ++ p
	pacmaninstall p = "pacman -S --noconfirm --needed " ++ p

	debdeps Cabal =
		[ "gnupg"
		-- Below are the same deps listed in debian/control.
		, "ghc"
		, "cabal-install"
		, "libghc-async-dev"
		, "libghc-split-dev"
		, "libghc-hslogger-dev"
		, "libghc-unix-compat-dev"
		, "libghc-ansi-terminal-dev"
		, "libghc-ifelse-dev"
		, "libghc-network-dev"
		, "libghc-mtl-dev"
		, "libghc-transformers-dev"
		, "libghc-exceptions-dev"
		, "libghc-stm-dev"
		, "libghc-text-dev"
		, "libghc-hashable-dev"
		]
	debdeps Stack =
		[ "gnupg"
		, "haskell-stack"
		]

	fbsddeps Cabal =
		[ "gnupg"
		, "ghc"
		, "hs-cabal-install"
		, "hs-async"
		, "hs-split"
		, "hs-hslogger"
		, "hs-unix-compat"
		, "hs-ansi-terminal"
		, "hs-IfElse"
		, "hs-network"
		, "hs-mtl"
		, "hs-transformers-base"
		, "hs-exceptions"
		, "hs-stm"
		, "hs-text"
		, "hs-hashable"
		]
	fbsddeps Stack =
		[ "gnupg"
		, "stack"
		]

	archlinuxdeps Cabal =
		[ "gnupg"
		, "ghc"
		, "cabal-install"
		, "haskell-async"
		, "haskell-split"
		, "haskell-hslogger"
		, "haskell-unix-compat"
		, "haskell-ansi-terminal"
		, "haskell-hackage-security"
		, "haskell-ifelse"
		, "haskell-network"
		, "haskell-mtl"
		, "haskell-transformers-base"
		, "haskell-exceptions"
		, "haskell-stm"
		, "haskell-text"
		, "hashell-hashable"
		]
	archlinuxdeps Stack = 
		[ "gnupg"
		, "stack"
		]

installGitCommand :: Maybe System -> ShellCommand
installGitCommand msys = case msys of
	(Just (System (Debian _ _) _)) -> use apt
	(Just (System (Buntish _) _)) -> use apt
	(Just (System (FreeBSD _) _)) -> use
		[ "ASSUME_ALWAYS_YES=yes pkg update"
		, "ASSUME_ALWAYS_YES=yes pkg install git"
		]
	(Just (System (ArchLinux) _)) -> use
		[ "pacman -S --noconfirm --needed git"]
	-- assume a debian derived system when not specified
	Nothing -> use apt
  where
	use cmds = "if ! git --version >/dev/null 2>&1; then " ++ intercalate " && " cmds ++ "; fi"
	apt =
		[ "apt-get update"
		, "DEBIAN_FRONTEND=noninteractive apt-get -qq --no-install-recommends --no-upgrade -y install git"
		]

-- Build propellor, and symlink the built binary to ./propellor.
--
-- When the Host has a Buildsystem specified it is used. If none is
-- specified, look at git config propellor.buildsystem.
buildPropellor :: Maybe Host -> IO ()
buildPropellor mh = unlessM (actionMessage "Propellor build" build) $
	errorMessage "Propellor build failed!"
  where
	msys = case fmap (fromInfo . hostInfo) mh of
		Just (InfoVal sys) -> Just sys
		_ -> Nothing

	build = catchBoolIO $ do
		case fromInfo (maybe mempty hostInfo mh) of
			NoInfoVal -> do			
				bs <- getGitConfigValue "propellor.buildsystem"
				case bs of
					Just "stack" -> stackBuild msys
					_ -> cabalBuild msys
			InfoVal bs -> case getBuilder bs of
				Cabal -> cabalBuild msys
				Stack -> stackBuild msys

-- For speed, only runs cabal configure when it's not been run before.
-- If the build fails cabal may need to have configure re-run.
--
-- If the cabal configure fails, and a System is provided, installs
-- dependencies and retries.
cabalBuild :: Maybe System -> IO Bool
cabalBuild msys = do
	make "dist/setup-config" ["propellor.cabal"] cabal_configure
	unlessM cabal_build $
		unlessM (cabal_configure <&&> cabal_build) $
			error "cabal build failed"
	-- For safety against eg power loss in the middle of the build,
	-- make a copy of the binary, and move it into place atomically.
	-- This ensures that the propellor symlink only ever points at
	-- a binary that is fully built. Also, avoid ever removing
	-- or breaking the symlink.
	--
	-- Need cp -a to make build timestamp checking work.
	unlessM (boolSystem "cp" [Param "-af", Param cabalbuiltbin, Param (tmpfor safetycopy)]) $
		error "cp of binary failed"
	rename (tmpfor safetycopy) safetycopy
	symlinkPropellorBin safetycopy
	return True
  where
	cabalbuiltbin = "dist/build/propellor-config/propellor-config"
	safetycopy = cabalbuiltbin ++ ".built"
	cabal_configure = ifM (cabal ["configure"])
		( return True
		, case msys of
			Nothing -> return False
			Just sys ->
				boolSystem "sh" [Param "-c", Param (depsCommand (Robustly Cabal) (Just sys))]
					<&&> cabal ["configure"]
		)
	-- The -j1 is to only run one job at a time -- in some situations,
	-- eg in qemu, ghc does not run reliably in parallel.
	cabal_build = cabal ["build", "-j1", "propellor-config"]

stackBuild :: Maybe System -> IO Bool
stackBuild _msys = do
	createDirectoryIfMissing True builddest
	ifM (stack buildparams)
		( do
			symlinkPropellorBin (builddest </> "propellor-config")
			return True
		, return False
		)
  where
 	builddest = ".built"
	buildparams =
		[ "--local-bin-path", builddest
		, "build"
		, ":propellor-config" -- only build config program
		, "--copy-bins"
		]

-- Atomic symlink creation/update.
symlinkPropellorBin :: FilePath -> IO ()
symlinkPropellorBin bin = do
	createSymbolicLink bin (tmpfor dest)
	rename (tmpfor dest) dest
  where
	dest = "propellor"

tmpfor :: FilePath -> FilePath
tmpfor f = f ++ ".propellortmp"

make :: FilePath -> [FilePath] -> IO Bool -> IO ()
make dest srcs builder = do
	dt <- getmtime dest
	st <- mapM getmtime srcs
	when (dt == Nothing || any (> dt) st) $
		unlessM builder $
			error $ "failed to make " ++ dest
  where
	getmtime = catchMaybeIO . getModificationTime

cabal :: [String] -> IO Bool
cabal = boolSystem "cabal" . map Param

stack :: [String] -> IO Bool
stack = boolSystem "stack" . map Param
