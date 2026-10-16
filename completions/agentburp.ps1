# PowerShell Tab-Completion for agentburp
# Developed by JOJIN JOHN
# Add to your $PROFILE:
# . path/to/agentburp.ps1

Register-ArgumentCompleter -Native -CommandName agentburp -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $subcommands = @(
        'proxy', 'hist', 'repeat', 'fuzz', 'diff',
        'scan', 'report', 'workspace', 'mcp-serve'
    )

    $elements = $commandAst.Elements
    if ($elements.Count -le 2) {
        $subcommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    $sub = $elements[1].Value
    switch ($sub) {
        'proxy' {
            @('start', '--addr', '--scope') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'hist' {
            @('list', 'show', '--host', '--method', '--status', '--body', '--limit') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'repeat' {
            @('--set', '--body', '--scope') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'fuzz' {
            @('--param', '--wordlist', '--range-from', '--range-to', '--anomalies', '--confirm', '--scope') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'report' {
            @('--format', 'hackerone', 'bugcrowd', 'generic', '--finding-id') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'workspace' {
            @('use', 'current') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        'mcp-serve' {
            @('--scope') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
}
