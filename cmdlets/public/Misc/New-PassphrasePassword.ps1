<#
.SYNOPSIS
  Generates a passphrase-style password using random words.

.DESCRIPTION
  The New-PassphrasePassword function creates a password by joining random words from a word list.
  You can specify the number of words, a separator character, and optionally include a random number or capitalize each word.
  The word list is sourced from the MSFT LAPS long word list https://www.microsoft.com/en-us/download/details.aspx?id=105762

.PARAMETER Length
  The number of words to include in the passphrase (default is 4, range 1-10).

.PARAMETER Separator
  The character to use between words in the passphrase (default is '-').

.PARAMETER includeNumber
  If specified, a random number will be appended to one of the words.

.PARAMETER includeCapital
  If specified, each word will be capitalized.

.EXAMPLE
  New-PassphrasePassword -Length 3 -Separator '_' -includeNumber -includeCapital

  Generates a passphrase with 3 capitalized words, separated by underscores, and a random number added to one word.

.EXAMPLE
  New-PassphrasePassword

  Generates a passphrase with 4 lowercase words separated by hyphens.

.NOTES
  Author: Jeremy Putman
  Last Updated: 2025-10-12
#>
function New-PassphrasePassword{
  [cmdletbinding()]
  param(
    [Parameter()][ValidateRange(1,10)][int]$Length = 4,
    [Parameter()][ValidateSet('-','_','|','*','')][string]$Separator = '-',
    [Parameter()][switch]$includeNumber,
    [Parameter()][switch]$includeCapital
  )
  # Get the word list from the supporting files
  $wordListPath = Join-Path -Path $PSScriptRoot -ChildPath "SupportFiles\wordlist.txt"
  # Get Word list contents
  $words = Get-Content -Path $wordListPath
  # Initialize an array to hold selected words
  $passphraseWords = [System.Collections.Generic.List[string]]::new()
  # Randomly select words from the list if selected to include a number
  if($includeNumber){
    $random_word = Get-Random -Minimum 0 -Maximum $Length
    $ranndom_number = Get-Random -Minimum 1 -Maximum 10
  }
  for ($i = 0; $i -lt $Length; $i++) {
    $randomWord = $words | Get-Random
    # Title case the words if selected
    if($includeCapital){
      $randomWord = [CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($randomWord.ToLower())
    }
    if($includeNumber -and $i -eq $random_word){
      $randomWord = "$($randomWord)$($ranndom_number)"
    }
    $passphraseWords.Add($randomWord)
  }
  # Return the joined passphrase
  return $passphraseWords -join $Separator 
}