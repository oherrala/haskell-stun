module Main where

import           Control.Monad           (void)
import           Language.Haskell.HLint3

main :: IO ()
main = void $ hlint ["src", "test"]
