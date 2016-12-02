import           Language.Haskell.HLint3
import           System.Exit

main :: IO ()
main = do
  ideas <- hlint ["app", "src", "test"]
  if null ideas
    then exitSuccess
    else exitFailure
