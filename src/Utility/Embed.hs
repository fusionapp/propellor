{-# LANGUAGE TemplateHaskell #-}
module Utility.Embed where

import Language.Haskell.TH
import qualified Data.FileEmbed as FE

sourceFile :: FilePath -> Q Exp
sourceFile path = return . AppE (VarE 'lines) =<< FE.embedStringFile path
